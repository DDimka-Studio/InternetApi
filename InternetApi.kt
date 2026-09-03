package ddimka_studio.test

import ddimka_studio.test.internal.DnsResolver
import ddimka_studio.test.internal.Socks5Handler
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

sealed class DnsStrategy {
    object System : DnsStrategy()
    data class Custom(val address: String) : DnsStrategy()
}

enum class TransportProtocol {
    TCP, UDP
}

sealed class ProxyConfig {
    object None : ProxyConfig()
    data class Socks5(val host: String, val port: Int) : ProxyConfig()
}

data class SocketConfig(
    val address: String,
    val port: Int,
    val protocol: TransportProtocol,
    val proxy: ProxyConfig = ProxyConfig.None,
    val useSSL: Boolean = false,
    val timeoutMs: Int = 5000
)

interface BaseSocket {
    fun getInputStream(): InputStream
    fun getOutputStream(): OutputStream
    suspend fun write(data: ByteArray)
    suspend fun read(bufferSize: Int = 1024): ByteArray
    suspend fun readFully(): ByteArray
    fun close()
}

object InternetAPI {
    private var defaultDns: DnsStrategy = DnsStrategy.System

    fun setDefaultDns(strategy: DnsStrategy) {
        defaultDns = strategy
    }

    // Tried, in order, ONLY when the system resolver itself fails (see below) - not used
    // up-front, since the system resolver is normally correct and often faster (cached,
    // DHCP/Private-DNS aware). These are last-resort fallbacks, queried via raw UDP DNS
    // (DnsResolver.Custom), which is a completely different code path from
    // InetAddress.getByName(): no netd, no per-app resolver policy, just a UDP packet this
    // app's own socket sends and parses itself. If the system resolver is being intercepted
    // or restricted for this app specifically (some custom ROMs/firewalls apply policies at
    // the getaddrinfo/netd layer that a raw socket-level DNS query simply isn't subject to),
    // this fallback resolves it without needing to add the app to your firewall exceptions.
    private val fallbackDnsServers = listOf("1.1.1.1", "8.8.8.8")

    suspend fun resolve(domain: String, customDns: String? = null): String = withContext(Dispatchers.IO) {
        val strategy = if (customDns != null) DnsStrategy.Custom(customDns) else defaultDns

        if (strategy != DnsStrategy.System) {
            return@withContext DnsResolver.resolve(domain, strategy)
        }

        try {
            DnsResolver.resolve(domain, DnsStrategy.System)
        } catch (systemFailure: Exception) {
            val fallbackErrors = mutableListOf<String>()
            for (server in fallbackDnsServers) {
                try {
                    return@withContext DnsResolver.resolve(domain, DnsStrategy.Custom(server))
                } catch (e: Exception) {
                    fallbackErrors.add("$server: ${e.message}")
                }
            }
            // Every fallback also failed - this domain is genuinely unreachable (or every DNS
            // path is blocked), not just the system resolver specifically. Surface the
            // ORIGINAL system-resolver error, but include the fallback failures in the message
            // so they're visible in logcat/UI without needing extra debug steps.
            val msg = "System DNS failed for $domain. Fallbacks also failed: ${fallbackErrors.joinToString(", ")}"
            throw Exception(msg, systemFailure)
        }
    }

    suspend fun openSocket(config: SocketConfig): BaseSocket = withContext(Dispatchers.IO) {
        val cleanAddress = config.address.removePrefix("http://").removePrefix("https://").substringBefore("/")
        val host = cleanAddress.substringBefore(":")

        val resolvedIp = if (host.endsWith(".onion")) {
            if (config.proxy !is ProxyConfig.Socks5) {
                throw IllegalArgumentException(".onion addresses require a SOCKS5 proxy")
            }
            host
        } else {
            resolve(host)
        }

        if (config.protocol == TransportProtocol.UDP) {
            if (config.proxy is ProxyConfig.Socks5) {
                throw UnsupportedOperationException("UDP via SOCKS5 proxy is currently not supported")
            }
            if (config.useSSL) {
                throw IllegalArgumentException("SSL/TLS is not supported for plain UDP sockets")
            }

            val socket = DatagramSocket()
            val inetAddress = InetAddress.getByName(resolvedIp)
            return@withContext UdpSocketWrapper(socket, inetAddress, config.port, config.timeoutMs)
        }

        // TCP Socket handling
        var socket = Socket()
        when (val proxy = config.proxy) {
            is ProxyConfig.Socks5 -> {
                socket.connect(InetSocketAddress(proxy.host, proxy.port), config.timeoutMs)
                Socks5Handler.performHandshake(socket, resolvedIp, config.port)
            }
            ProxyConfig.None -> {
                socket.connect(InetSocketAddress(resolvedIp, config.port), config.timeoutMs)
            }
        }
        // Bounds every subsequent blocking read (including the SSL handshake below and any
        // read()/readFully() the caller does afterward) - without this, a server that accepts
        // the connection but then never sends anything (or never closes it) hangs forever, same
        // failure mode already hit once with the plain HttpURLConnection download path.
        socket.soTimeout = config.timeoutMs

        if (config.useSSL) {
            val sslSocket = (SSLSocketFactory.getDefault() as SSLSocketFactory)
                .createSocket(socket, host, config.port, true) as SSLSocket
            sslSocket.soTimeout = config.timeoutMs
            sslSocket.startHandshake()

            // Hostname verification
            if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(host, sslSocket.session)) {
                throw Exception("Hostname verification failed for $host")
            }

            socket = sslSocket
        }

        TcpSocketWrapper(socket)
    }

    /**
     * Downloads a file from the given URL and saves it to the specified destination.
     *
     * @param url Download target URL (HTTP / HTTPS).
     * @param destinationFile Local destination File (creates parent directories if needed).
     * @param followRedirects Whether HTTP redirects (301, 302, etc.) should be followed.
     * @param maxRedirects Maximum number of allowed redirects.
     * @param proxy Proxy configuration (Socks5 or None).
     * @param onProgress Callback receiving (bytesDownloaded, totalBytes or -1 if unknown).
     */
    suspend fun downloadFile(
        url: String,
        destinationFile: File,
        followRedirects: Boolean = true,
        maxRedirects: Int = 5,
        proxy: ProxyConfig = ProxyConfig.None,
        onProgress: ((bytesDownloaded: Long, totalBytes: Long) -> Unit)? = null
    ): Result<File> = withContext(Dispatchers.IO) {
        var currentUrl = url
        var redirects = 0

        while (redirects <= maxRedirects) {
            try {
                // Parse URL
                val isHttps = currentUrl.startsWith("https://", ignoreCase = true)
                val cleanUrl = currentUrl.removePrefix("http://").removePrefix("https://")
                val hostPath = cleanUrl.split("/", limit = 2)
                val hostPort = hostPath[0].split(":", limit = 2)
                val host = hostPort[0]
                val port = hostPort.getOrNull(1)?.toIntOrNull() ?: if (isHttps) 443 else 80
                val path = if (hostPath.size > 1) "/${hostPath[1]}" else "/"

                val config = SocketConfig(host, port, TransportProtocol.TCP, proxy, useSSL = isHttps)
                val socket = openSocket(config)
                val inputStream = socket.getInputStream()

                // Send HTTP GET request
                val request = "GET $path HTTP/1.1\r\n" +
                        "Host: $host\r\n" +
                        "User-Agent: InternetAPI/1.0\r\n" +
                        "Accept: */*\r\n" +
                        "Connection: close\r\n\r\n"

                socket.write(request.toByteArray())

                // Read HTTP response headers
                val headers = readHeaders(inputStream)
                val statusLine = headers.firstOrNull() ?: throw Exception("Empty response from server")
                val statusCode = statusLine.split(" ").getOrNull(1)?.toIntOrNull() ?: 0

                // Handle HTTP redirects (3xx)
                if (followRedirects && statusCode in 300..399) {
                    val locationHeader = headers.find { it.startsWith("Location:", ignoreCase = true) }
                    val newLocation = locationHeader?.substringAfter(":")?.trim()
                    socket.close()

                    if (newLocation != null) {
                        currentUrl = if (newLocation.startsWith("http://") || newLocation.startsWith("https://")) {
                            newLocation
                        } else {
                            val scheme = if (isHttps) "https" else "http"
                            if (newLocation.startsWith("/")) "$scheme://$host$newLocation" else "$scheme://$host/$newLocation"
                        }
                        redirects++
                        continue
                    } else {
                        return@withContext Result.failure(Exception("Redirect $statusCode received without Location header"))
                    }
                }

                if (statusCode !in 200..299) {
                    socket.close()
                    return@withContext Result.failure(Exception("HTTP error $statusCode: $statusLine"))
                }

                // Extract Content-Length if present
                val contentLength = headers.find { it.startsWith("Content-Length:", ignoreCase = true) }
                    ?.substringAfter(":")?.trim()?.toLongOrNull() ?: -1L

                // Plenty of mirrors (and pretty much any HTTPS CDN in front of a dynamic
                // backend) send "Transfer-Encoding: chunked" instead of Content-Length. When
                // that happens the body on the wire is NOT the raw file - it's interleaved with
                // hex chunk-size lines and \r\n framing (see readChunkedBody). The old code here
                // ignored this entirely and copied the socket stream byte-for-byte into the
                // destination file whenever contentLength was -1, which silently wrote that
                // chunk framing straight into the tarball - "download succeeds" but the archive
                // is corrupt. Must be decoded, not passed through.
                val isChunked = headers.any {
                    it.startsWith("Transfer-Encoding:", ignoreCase = true) && it.contains("chunked", ignoreCase = true)
                }

                // Ensure parent directories exist
                destinationFile.parentFile?.mkdirs()

                // Stream response body directly to target file
                var totalRead = 0L
                try {
                    FileOutputStream(destinationFile).use { fileOut ->
                        if (isChunked) {
                            readChunkedBody(inputStream) { buf, n ->
                                fileOut.write(buf, 0, n)
                                totalRead += n
                                // Total size isn't known ahead of time for chunked responses -
                                // report -1 so callers show "downloaded so far" without a bogus total.
                                onProgress?.invoke(totalRead, -1L)
                            }
                        } else {
                            val buffer = ByteArray(8192)
                            var bytesRead: Int

                            while (inputStream.read(buffer).also { bytesRead = it } != -1) {
                                fileOut.write(buffer, 0, bytesRead)
                                totalRead += bytesRead
                                onProgress?.invoke(totalRead, contentLength)
                            }
                        }
                        fileOut.flush()
                    }
                } finally {
                    socket.close()
                }

                // A dropped connection mid-transfer ends the read loop the same way a clean
                // finish does (read() just returns -1 either way) - without checking the byte
                // count against Content-Length, a truncated download looks identical to a
                // successful one here, and only fails much later with a confusing error deep
                // inside whatever tries to parse the (corrupt) file.
                if (contentLength >= 0 && totalRead != contentLength) {
                    destinationFile.delete()
                    return@withContext Result.failure(
                        Exception("Incomplete download: got $totalRead of $contentLength bytes")
                    )
                }

                return@withContext Result.success(destinationFile)

            } catch (e: Exception) {
                return@withContext Result.failure(e)
            }
        }

        Result.failure(Exception("Exceeded maximum redirect count of $maxRedirects"))
    }

    /**
     * Reads HTTP headers character-by-character until reaching \r\n\r\n
     */
    private fun readHeaders(inputStream: InputStream): List<String> {
        val headersBuilder = StringBuilder()
        var lastFourBytes = 0

        while (true) {
            val byte = inputStream.read()
            if (byte == -1) break
            headersBuilder.append(byte.toChar())

            lastFourBytes = (lastFourBytes shl 8) or byte
            if (lastFourBytes == 0x0D0A0D0A) { // \r\n\r\n
                break
            }
        }

        return headersBuilder.toString().trim().split("\r\n")
    }

    /** Reads a single CRLF-terminated line from a byte stream (chunk-size lines, chunk trailers). */
    private fun readChunkedLine(input: InputStream): String {
        val sb = StringBuilder()
        while (true) {
            val b = input.read()
            if (b == -1) break // stream ended mid-line - readChunkedBody's caller will fail on the malformed size
            if (b == '\r'.code) continue
            if (b == '\n'.code) break
            sb.append(b.toChar())
        }
        return sb.toString()
    }

    /**
     * Decodes an HTTP/1.1 "Transfer-Encoding: chunked" body: each chunk is prefixed by its size
     * in hex (optionally followed by ";extension", which we ignore) on its own CRLF-terminated
     * line, followed by that many raw bytes, followed by a CRLF, repeating until a chunk of size
     * 0 - which may itself be followed by trailer headers, terminated by a blank line.
     *
     * [onChunk] is invoked once per read (not necessarily once per logical chunk) with a shared
     * buffer and the valid length in it, mirroring InputStream.read()'s (buffer, length)
     * convention - callers write buf[0 until n] wherever they need it (a file, an in-memory
     * accumulator, etc.) instead of this function allocating and handing back a full byte array.
     * Returns the total number of decoded body bytes.
     */
    private fun readChunkedBody(input: InputStream, onChunk: (buf: ByteArray, n: Int) -> Unit): Long {
        var total = 0L
        val buffer = ByteArray(8192)
        while (true) {
            val sizeLine = readChunkedLine(input).substringBefore(';').trim()
            val chunkSize = sizeLine.toIntOrNull(16)
                ?: throw IOException("Malformed chunk size line: '$sizeLine'")

            if (chunkSize == 0) {
                // Optional trailer headers after the terminating zero-size chunk - discard until
                // the blank line that ends them (same terminator shape as the main header block).
                while (readChunkedLine(input).isNotEmpty()) { /* discard trailer header */ }
                break
            }

            var remaining = chunkSize
            while (remaining > 0) {
                val n = input.read(buffer, 0, minOf(buffer.size, remaining))
                if (n < 0) throw IOException("Unexpected end of stream while reading a chunk")
                onChunk(buffer, n)
                total += n
                remaining -= n
            }
            readChunkedLine(input) // each chunk's data is followed by a trailing CRLF
        }
        return total
    }

    /**
     * Performs a simple HTTP GET and returns the response body as a String.
     * Throws an Exception if the status code is not 2xx.
     */
    suspend fun fetchString(url: String, proxy: ProxyConfig = ProxyConfig.None): String = withContext(Dispatchers.IO) {
        val isHttps = url.startsWith("https://", ignoreCase = true)
        val cleanUrl = url.removePrefix("http://").removePrefix("https://")
        val hostPath = cleanUrl.split("/", limit = 2)
        val hostPort = hostPath[0].split(":", limit = 2)
        val host = hostPort[0]
        val port = hostPort.getOrNull(1)?.toIntOrNull() ?: if (isHttps) 443 else 80
        val path = if (hostPath.size > 1) "/${hostPath[1]}" else "/"

        val config = SocketConfig(host, port, TransportProtocol.TCP, proxy, useSSL = isHttps)
        val socket = openSocket(config)
        val inputStream = socket.getInputStream()

        try {
            val request = "GET $path HTTP/1.1\r\n" +
                    "Host: $host\r\n" +
                    "User-Agent: InternetAPI/1.0\r\n" +
                    "Connection: close\r\n\r\n"

            socket.write(request.toByteArray())

            val headers = readHeaders(inputStream)
            val statusLine = headers.firstOrNull() ?: throw Exception("Empty response")
            val statusCode = statusLine.split(" ").getOrNull(1)?.toIntOrNull() ?: 0

            if (statusCode !in 200..299) {
                throw Exception("HTTP $statusCode: $statusLine")
            }

            val isChunked = headers.any {
                it.startsWith("Transfer-Encoding:", ignoreCase = true) && it.contains("chunked", ignoreCase = true)
            }

            if (isChunked) {
                val body = ByteArrayOutputStream()
                readChunkedBody(inputStream) { buf, n -> body.write(buf, 0, n) }
                String(body.toByteArray())
            } else {
                // Read the rest of the stream as the body
                String(inputStream.readBytes())
            }
        } finally {
            socket.close()
        }
    }

    suspend fun httpGet(
        url: String,
        followRedirects: Boolean = true,
        maxRedirects: Int = 5,
        proxy: ProxyConfig = ProxyConfig.None
    ): Result<String> = withContext(Dispatchers.IO) {
        var currentUrl = url
        var redirects = 0
        val history = StringBuilder()

        while (redirects <= maxRedirects) {
            try {
                val cleanUrl = currentUrl.removePrefix("http://").removePrefix("https://")
                val hostPath = cleanUrl.split("/", limit = 2)
                val hostPort = hostPath[0].split(":", limit = 2)
                val host = hostPort[0]
                val isHttps = currentUrl.startsWith("https", ignoreCase = true)
                val port = hostPort.getOrNull(1)?.toIntOrNull() ?: if (isHttps) 443 else 80
                val path = if (hostPath.size > 1) "/${hostPath[1]}" else "/"

                val config = SocketConfig(host, port, TransportProtocol.TCP, proxy, useSSL = isHttps)
                val socket = openSocket(config)

                val request = "GET $path HTTP/1.1\r\nHost: $host\r\nConnection: close\r\nUser-Agent: InternetAPI/1.0\r\n\r\n"
                socket.write(request.toByteArray())

                val rawResponse = socket.readFully()
                socket.close()

                val responseStr = String(rawResponse)
                history.append("--> Requesting: $currentUrl\n")

                val lines = responseStr.split("\r\n")
                if (lines.isEmpty()) return@withContext Result.failure(Exception("Empty response"))

                val statusLine = lines[0]
                val statusCode = statusLine.split(" ").getOrNull(1)?.toIntOrNull() ?: 0

                if (followRedirects && statusCode in 300..399) {
                    val locationHeader = lines.find { it.startsWith("Location:", ignoreCase = true) }
                    val newLocation = locationHeader?.substringAfter(":")?.trim()

                    if (newLocation != null) {
                        currentUrl = if (newLocation.startsWith("http")) newLocation else {
                            val base = if (currentUrl.endsWith("/")) currentUrl.dropLast(1) else currentUrl
                            if (newLocation.startsWith("/")) base + newLocation else "$base/$newLocation"
                        }
                        redirects++
                        history.append("Redirect $statusCode to: $newLocation\n")
                        continue
                    }
                }

                return@withContext Result.success("${history}\nFinal Response:\n$responseStr")

            } catch (e: Exception) {
                return@withContext Result.failure(Exception("${history}Error: ${e.message}", e))
            }
        }
        Result.failure(Exception("Too many redirects: $maxRedirects"))
    }

    suspend fun httpPost(
        url: String,
        jsonBody: String,
        proxy: ProxyConfig = ProxyConfig.None
    ): Result<String> = withContext(Dispatchers.IO) {
        try {
            val cleanUrl = url.removePrefix("http://").removePrefix("https://")
            val hostPath = cleanUrl.split("/", limit = 2)
            val hostPort = hostPath[0].split(":", limit = 2)
            val host = hostPort[0]
            val isHttps = url.startsWith("https", ignoreCase = true)
            val port = hostPort.getOrNull(1)?.toIntOrNull() ?: if (isHttps) 443 else 80
            val path = if (hostPath.size > 1) "/${hostPath[1]}" else "/"

            val config = SocketConfig(host, port, TransportProtocol.TCP, proxy, useSSL = isHttps)
            val socket = openSocket(config)

            val request = "POST $path HTTP/1.1\r\n" +
                    "Host: $host\r\n" +
                    "Content-Type: application/json\r\n" +
                    "Content-Length: ${jsonBody.toByteArray().size}\r\n" +
                    "Connection: close\r\n" +
                    "User-Agent: InternetAPI/1.0\r\n\r\n" +
                    jsonBody

            socket.write(request.toByteArray())

            val rawResponse = socket.readFully()
            socket.close()

            Result.success(String(rawResponse))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}

private class TcpSocketWrapper(private val socket: Socket) : BaseSocket {
    private val inputStream: InputStream = socket.getInputStream()
    private val outputStream: OutputStream = socket.getOutputStream()

    override fun getInputStream(): InputStream = inputStream
    override fun getOutputStream(): OutputStream = outputStream

    override suspend fun write(data: ByteArray) = withContext(Dispatchers.IO) {
        outputStream.write(data)
        outputStream.flush()
    }

    override suspend fun read(bufferSize: Int): ByteArray = withContext(Dispatchers.IO) {
        val buffer = ByteArray(bufferSize)
        val bytesRead = inputStream.read(buffer)
        if (bytesRead == -1) return@withContext byteArrayOf()
        buffer.copyOfRange(0, bytesRead)
    }

    override suspend fun readFully(): ByteArray = withContext(Dispatchers.IO) {
        inputStream.readBytes()
    }

    override fun close() {
        socket.close()
    }
}

private class UdpSocketWrapper(
    private val socket: DatagramSocket,
    private val remoteAddress: InetAddress,
    private val remotePort: Int,
    timeoutMs: Int
) : BaseSocket {

    init {
        socket.soTimeout = timeoutMs
        socket.connect(remoteAddress, remotePort)
    }

    override fun getInputStream(): InputStream {
        throw UnsupportedOperationException("Input streams are not supported for UDP sockets")
    }

    override fun getOutputStream(): OutputStream {
        throw UnsupportedOperationException("Output streams are not supported for UDP sockets")
    }

    override suspend fun write(data: ByteArray) = withContext(Dispatchers.IO) {
        val packet = DatagramPacket(data, data.size, remoteAddress, remotePort)
        socket.send(packet)
    }

    override suspend fun read(bufferSize: Int): ByteArray = withContext(Dispatchers.IO) {
        val buffer = ByteArray(bufferSize)
        val packet = DatagramPacket(buffer, buffer.size)
        try {
            socket.receive(packet)
            buffer.copyOfRange(0, packet.length)
        } catch (e: Exception) {
            byteArrayOf()
        }
    }

    override suspend fun readFully(): ByteArray = withContext(Dispatchers.IO) {
        // Reads maximum datagram payload buffer size (65535 bytes)
        read(65535)
    }

    override fun close() {
        socket.close()
    }
}