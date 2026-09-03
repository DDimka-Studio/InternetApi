package ddimka_studio.test.internal

import android.util.Log
import ddimka_studio.test.DnsStrategy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.Random

object DnsResolver {
    private const val TAG = "ETL-DNS"

    suspend fun resolve(domain: String, strategy: DnsStrategy): String = withContext(Dispatchers.IO) {
        Log.d(TAG, "Resolving $domain using strategy $strategy")
        when (strategy) {
            is DnsStrategy.System -> {
                try {
                    InetAddress.getByName(domain).hostAddress ?: throw Exception("Failed to resolve $domain")
                } catch (e: Exception) {
                    Log.w(TAG, "System resolution failed for $domain", e)
                    throw e
                }
            }
            is DnsStrategy.Custom -> {
                try {
                    resolveCustom(domain, strategy.address)
                } catch (e: Exception) {
                    throw Exception("Failed to resolve $domain via ${strategy.address}: ${e.message}", e)
                }
            }
        }
    }

    private fun resolveCustom(domain: String, dnsServer: String): String {
        val socket = DatagramSocket()
        socket.soTimeout = 5000
        val dnsAddress = InetAddress.getByName(dnsServer)
        // Restricts this socket to only ever receive packets FROM dnsAddress:53 - the OS
        // filters anything else out before it reaches us, which is a stronger guarantee than
        // checking the source address ourselves after the fact.
        socket.connect(dnsAddress, 53)

        try {
            val queryId = Random().nextInt(65535)
            val query = createDnsQuery(domain, queryId)
            val packet = DatagramPacket(query, query.size, dnsAddress, 53)
            try {
                socket.send(packet)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to send DNS query to $dnsServer: ${e.message}", e)
                throw e
            }

            // Plain UDP DNS has no authentication - anyone who can get a packet to this socket
            // before the real DNS server's reply arrives can spoof the answer (classic cache/
            // response poisoning), which is a real integrity concern here since a spoofed reply
            // could point rootfs downloads at an attacker-controlled host. The transaction id
            // in the header is the one thing tying a response to OUR specific query - the
            // previous version never checked it and would happily accept ANY packet that showed
            // up first. Loop until we see a response whose id actually matches, discarding
            // anything else, instead of trusting the first thing that arrives.
            val deadlineAt = System.currentTimeMillis() + socket.soTimeout
            while (true) {
                val remaining = (deadlineAt - System.currentTimeMillis()).toInt()
                if (remaining <= 0) {
                    val msg = "Timed out waiting for a DNS reply matching query id $queryId from $dnsServer"
                    Log.w(TAG, msg)
                    throw Exception(msg)
                }
                socket.soTimeout = remaining

                val responseBuffer = ByteArray(1024)
                val responsePacket = DatagramPacket(responseBuffer, responseBuffer.size)
                try {
                    socket.receive(responsePacket)
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to receive DNS reply from $dnsServer: ${e.message}", e)
                    throw e
                }
                if (responsePacket.length < 2) continue

                val responseId = ((responseBuffer[0].toInt() and 0xFF) shl 8) or (responseBuffer[1].toInt() and 0xFF)
                if (responseId != queryId) continue // not an answer to our query - ignore and keep waiting

                return parseDnsResponse(responseBuffer, responsePacket.length)
            }
        } finally {
            socket.close() // previously never closed at all - leaked a socket per lookup
        }
    }

    private fun createDnsQuery(domain: String, id: Int): ByteArray {
        val query = mutableListOf<Byte>()

        // Header
        query.add((id shr 8).toByte())
        query.add((id and 0xFF).toByte())
        query.add(0x01.toByte()) // Flags: standard query, recursion desired
        query.add(0x00.toByte())
        query.add(0x00.toByte()) // QDCOUNT = 1
        query.add(0x01.toByte())
        query.add(0x00.toByte()) // ANCOUNT = 0
        query.add(0x00.toByte())
        query.add(0x00.toByte()) // NSCOUNT = 0
        query.add(0x00.toByte())
        query.add(0x00.toByte()) // ARCOUNT = 0
        query.add(0x00.toByte())

        // Question
        domain.split(".").forEach { label ->
            query.add(label.length.toByte())
            label.forEach { query.add(it.code.toByte()) }
        }
        query.add(0x00.toByte()) // Terminating 0 length label

        query.add(0x00.toByte()) // QTYPE = A (1)
        query.add(0x01.toByte())
        query.add(0x00.toByte()) // QCLASS = IN (1)
        query.add(0x01.toByte())

        return query.toByteArray()
    }

    private fun parseDnsResponse(buffer: ByteArray, length: Int): String {
        // Very simplified DNS response parsing
        // We skip the header (12 bytes) and the question (which we sent)
        var pos = 12
        
        // Skip question
        while (buffer[pos] != 0x00.toByte()) {
            pos += buffer[pos].toInt() + 1
        }
        pos += 5 // Skip terminating 0, QTYPE, QCLASS

        // Answer Section
        // We expect at least one A record
        if (pos + 10 > length) throw Exception("Invalid DNS response")
        
        // Skip NAME (could be a pointer)
        if ((buffer[pos].toInt() and 0xC0) == 0xC0) {
            pos += 2
        } else {
            while (buffer[pos] != 0x00.toByte()) {
                pos += buffer[pos].toInt() + 1
            }
            pos++
        }
        
        val type = ((buffer[pos].toInt() and 0xFF) shl 8) or (buffer[pos + 1].toInt() and 0xFF)
        pos += 8 // Skip TYPE, CLASS, TTL
        
        val rdLength = ((buffer[pos].toInt() and 0xFF) shl 8) or (buffer[pos + 1].toInt() and 0xFF)
        pos += 2

        if (type == 1 && rdLength == 4) { // A record
            val ip = "${buffer[pos].toInt() and 0xFF}.${buffer[pos + 1].toInt() and 0xFF}.${buffer[pos + 2].toInt() and 0xFF}.${buffer[pos + 3].toInt() and 0xFF}"
            return ip
        }
        
        throw Exception("No A record found in DNS response")
    }
}
