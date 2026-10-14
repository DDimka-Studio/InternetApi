package ddimka_studio.internetapi.internal

import ddimka_studio.internetapi.DnsStrategy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.IDN
import java.net.InetAddress
import java.security.SecureRandom

object DnsResolver {
    private const val DNS_PORT = 53
    private const val TIMEOUT_MS = 5000
    private val random = SecureRandom()

    suspend fun resolve(domain: String, strategy: DnsStrategy): String = withContext(Dispatchers.IO) {
        when (strategy) {
            is DnsStrategy.System ->
                InetAddress.getByName(domain).hostAddress ?: throw Exception("Failed to resolve $domain")
            is DnsStrategy.Custom -> try {
                resolveCustom(domain, strategy.address)
            } catch (e: Exception) {
                throw Exception("Failed to resolve $domain via ${strategy.address}: ${e.message}", e)
            }
        }
    }

    private fun resolveCustom(domain: String, dnsServer: String): String {
        val dnsAddress = InetAddress.getByName(dnsServer)
        val queryId = random.nextInt(0x10000)
        val query = createDnsQuery(domain, queryId)

        val socket = DatagramSocket()
        try {
            socket.soTimeout = TIMEOUT_MS
            // connect() makes the OS drop datagrams that do not come from the DNS server.
            socket.connect(dnsAddress, DNS_PORT)
            socket.send(DatagramPacket(query, query.size, dnsAddress, DNS_PORT))

            val deadline = System.currentTimeMillis() + TIMEOUT_MS
            while (true) {
                val remaining = (deadline - System.currentTimeMillis()).toInt()
                if (remaining <= 0) throw Exception("Timed out waiting for a DNS reply from $dnsServer")
                socket.soTimeout = remaining

                val buffer = ByteArray(4096)
                val packet = DatagramPacket(buffer, buffer.size)
                socket.receive(packet)
                if (packet.length < 12) continue
                // Plain UDP DNS is unauthenticated: only accept a reply whose transaction id matches our query.
                val replyId = ((buffer[0].toInt() and 0xFF) shl 8) or (buffer[1].toInt() and 0xFF)
                if (replyId != queryId) continue
                return parseDnsResponse(buffer, packet.length)
            }
        } finally {
            socket.close()
        }
    }

    private fun createDnsQuery(domain: String, id: Int): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(id ushr 8)
        out.write(id and 0xFF)
        out.write(0x01); out.write(0x00) // flags: standard query, recursion desired
        out.write(0x00); out.write(0x01) // QDCOUNT = 1
        out.write(0x00); out.write(0x00) // ANCOUNT
        out.write(0x00); out.write(0x00) // NSCOUNT
        out.write(0x00); out.write(0x00) // ARCOUNT

        // IDN.toASCII converts Unicode names to punycode, which is what goes on the wire.
        val ascii = IDN.toASCII(domain.trimEnd('.'))
        for (label in ascii.split('.')) {
            val bytes = label.toByteArray(Charsets.US_ASCII)
            require(bytes.isNotEmpty() && bytes.size <= 63) { "Invalid DNS label in '$domain'" }
            out.write(bytes.size)
            out.write(bytes)
        }
        out.write(0x00)                  // end of name
        out.write(0x00); out.write(0x01) // QTYPE = A
        out.write(0x00); out.write(0x01) // QCLASS = IN
        return out.toByteArray()
    }

    private fun parseDnsResponse(buffer: ByteArray, length: Int): String {
        val msg = DnsMessage(buffer, length)

        val flags = msg.u16(2)
        if ((flags and 0x8000) == 0) throw Exception("Not a DNS response")
        val rcode = flags and 0x000F
        if (rcode != 0) throw Exception("DNS server returned error code $rcode")

        var pos = 12
        // Skip the question section (we only ever send one question).
        repeat(msg.u16(4)) { pos = msg.skipName(pos) + 4 } // + QTYPE and QCLASS

        // Walk every answer record: the first one is often a CNAME, and the A record follows it.
        repeat(msg.u16(6)) {
            pos = msg.skipName(pos)
            val type = msg.u16(pos)
            val rdLength = msg.u16(pos + 8)
            val rdStart = pos + 10
            if (type == 1 && rdLength == 4) {
                return "${msg.u8(rdStart)}.${msg.u8(rdStart + 1)}.${msg.u8(rdStart + 2)}.${msg.u8(rdStart + 3)}"
            }
            pos = rdStart + rdLength
        }
        throw Exception("No A record found in DNS response")
    }
}

/** Bounds-checked reader over a raw DNS message. */
private class DnsMessage(private val buf: ByteArray, private val length: Int) {
    fun u8(i: Int): Int {
        if (i < 0 || i >= length) throw Exception("Truncated DNS response")
        return buf[i].toInt() and 0xFF
    }

    fun u16(i: Int): Int = (u8(i) shl 8) or u8(i + 1)

    /** Returns the offset just past the (possibly compressed) name that starts at [start]. */
    fun skipName(start: Int): Int {
        var pos = start
        while (true) {
            val len = u8(pos)
            if (len == 0) return pos + 1
            if ((len and 0xC0) == 0xC0) return pos + 2 // a compression pointer always ends the name
            pos += len + 1
        }
    }
}
