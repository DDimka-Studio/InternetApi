package ddimka_studio.internetapi.internal

import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.Inet6Address
import java.net.Socket

object Socks5Handler {
    private val IPV4 = Regex("^[0-9]{1,3}(\\.[0-9]{1,3}){3}$")

    /**
     * Performs a SOCKS5 CONNECT to [targetHost]:[targetPort] over an already-connected [socket].
     * Hostnames are sent as names (ATYP 0x03), so the proxy does the resolving; only IP literals are sent as addresses.
     */
    fun performHandshake(socket: Socket, targetHost: String, targetPort: Int) {
        val input = DataInputStream(socket.getInputStream())
        val output = DataOutputStream(socket.getOutputStream())

        // 1. Greeting: SOCKS version 5, one method offered: no authentication.
        output.writeByte(0x05)
        output.writeByte(0x01)
        output.writeByte(0x00)
        output.flush()

        // 2. Method selection reply.
        val version = input.readUnsignedByte()
        val method = input.readUnsignedByte()
        if (version != 0x05 || method != 0x00) {
            throw Exception("SOCKS5 negotiation failed. Version: $version, Method: $method")
        }

        // 3. CONNECT request.
        output.writeByte(0x05) // version
        output.writeByte(0x01) // command: CONNECT
        output.writeByte(0x00) // reserved
        when {
            targetHost.contains(':') -> {
                val address = Inet6Address.getByName(targetHost.removePrefix("[").removeSuffix("]").substringBefore('%'))
                output.writeByte(0x04)
                output.write(address.address)
            }
            IPV4.matches(targetHost) -> {
                val octets = targetHost.split('.').map { it.toInt() }
                require(octets.all { it in 0..255 }) { "Invalid IPv4 address: $targetHost" }
                output.writeByte(0x01)
                octets.forEach { output.writeByte(it) }
            }
            else -> {
                val name = targetHost.toByteArray(Charsets.US_ASCII)
                require(name.isNotEmpty() && name.size <= 255) { "Invalid SOCKS5 target host: '$targetHost'" }
                output.writeByte(0x03)
                output.writeByte(name.size)
                output.write(name)
            }
        }
        output.writeShort(targetPort)
        output.flush()

        // 4. Reply.
        val replyVersion = input.readUnsignedByte()
        val replyStatus = input.readUnsignedByte()
        if (replyVersion != 0x05 || replyStatus != 0x00) {
            throw Exception("SOCKS5 connection failed. Status: $replyStatus")
        }
        input.readUnsignedByte() // reserved
        when (input.readUnsignedByte()) {
            0x01 -> input.readFully(ByteArray(4))                              // BND.ADDR (IPv4)
            0x03 -> input.readFully(ByteArray(input.readUnsignedByte()))       // BND.ADDR (domain)
            0x04 -> input.readFully(ByteArray(16))                             // BND.ADDR (IPv6)
            else -> throw Exception("SOCKS5 reply has an unknown address type")
        }
        input.readUnsignedShort() // BND.PORT
    }
}
