package ddimka_studio.test.internal

import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.Socket

object Socks5Handler {
    fun performHandshake(socket: Socket, targetHost: String, targetPort: Int) {
        val input = DataInputStream(socket.getInputStream())
        val output = DataOutputStream(socket.getOutputStream())

        // 1. Version identifier/method selection message
        output.writeByte(0x05) // SOCKS version 5
        output.writeByte(0x01) // Number of methods
        output.writeByte(0x00) // No authentication
        output.flush()

        // 2. Method selection response
        val version = input.readByte().toInt()
        val method = input.readByte().toInt()
        if (version != 0x05 || method != 0x00) {
            throw Exception("SOCKS5 negotiation failed. Version: $version, Method: $method")
        }

        // 3. Request message
        output.writeByte(0x05) // SOCKS version 5
        output.writeByte(0x01) // Command: CONNECT
        output.writeByte(0x00) // Reserved
        
        // Address type
        if (targetHost.contains(":") || targetHost.contains("[")) {
            // IPv6
            output.writeByte(0x04)
            val cleanHost = targetHost.removePrefix("[").removePrefix("]").substringBefore("%")
            val address = java.net.Inet6Address.getByName(cleanHost)
            output.write(address.address)
        } else if (targetHost.matches(Regex("^[0-9.]+$"))) {
            // IPv4
            output.writeByte(0x01)
            val parts = targetHost.split(".")
            parts.forEach { output.writeByte(it.toInt()) }
        } else {
            // Domain name (covers .onion)
            output.writeByte(0x03)
            output.writeByte(targetHost.length)
            output.writeBytes(targetHost)
        }
        
        output.writeShort(targetPort)
        output.flush()

        // 4. Response message
        val respVersion = input.readByte().toInt()
        val respStatus = input.readByte().toInt()
        if (respVersion != 0x05 || respStatus != 0x00) {
            throw Exception("SOCKS5 connection failed. Status: $respStatus")
        }

        // Skip remaining response bytes (RSV, ATYP, BND.ADDR, BND.PORT)
        input.readByte() // RSV
        val atyp = input.readByte().toInt()
        when (atyp) {
            0x01 -> input.readFully(ByteArray(4)) // IPv4
            0x03 -> input.readFully(ByteArray(input.readByte().toInt())) // Domain
            0x04 -> input.readFully(ByteArray(16)) // IPv6
        }
        input.readShort() // Port
    }
}
