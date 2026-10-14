package ddimka_studio.internetapi

import ddimka_studio.internetapi.internal.DnsResolver
import ddimka_studio.internetapi.internal.Socks5Handler
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
import java.net.URI
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

private const val MAX_HEADER_BYTES = 64 * 1024

private data class HttpTarget(val https: Boolean, val host: String, val port: Int, val path: String) {
    val hostHeader: String
        get() = if (port == (if (https) 443 else 80)) host else "$host:$port"
}

private fun parseHttpUrl(url: String): HttpTarget {
    val uri = URI(url)
    val scheme = uri.scheme?.lowercase() ?: throw IllegalArgumentException("URL has no scheme: $url")
    require(scheme == "http" || scheme == "https") { "Unsupported scheme: $scheme" }
    val https = scheme == "https"
    val host = uri.host ?: throw IllegalArgumentException("URL has no host: $url")
    val port = if (uri.port != -1) uri.port else if (https) 443 else 80
    val path = (uri.rawPath?.takeIf { it.isNotEmpty() } ?: "/") + (uri.rawQuery?.let { "?$it" } ?: "")
    return HttpTarget(https, host, port, path)
}

private fun httpRequest(method: String, target: HttpTarget, body: ByteArray? = null): ByteArray {
    val head = StringBuilder()
        .append("$method ${target.path} HTTP/1.1\r\n")
        .append("Host: ${target.hostHeader}\r\n")
        .append("User-Agent: InternetAPI/1.0\r\n")
        .append("Accept: */*\r\n")
        .append("Connection: close\r\n")
    if (body != null) {
        head.append("Content-Type: application/json\r\n")
        head.append("Content-Length: ${body.size}\r\n")
    }
    head.append("\r\n")
    val headBytes = head.toString().toByteArray(Charsets.US_ASCII)
    return if (body == null) headBytes else headBytes + body
}

private fun parseStatusCode(statusLine: String): Int =
    statusLine.split(" ").getOrNull(1)?.toIntOrNull() ?: 0

private fun headerValue(headers: List<String>, name: String): String? =
    headers.firstOrNull { it.startsWith("$name:", ignoreCase = true) }?.substringAfter(':')?.trim()

private fun isChunked(headers: List<String>): Boolean =
    headerValue(headers, "Transfer-Encoding")?.contains("chunked", ignoreCase = true) == true

/** Reads an HTTP response head: lines up to and including the blank line. The first element is the status line. */
private fun readHeaders(input: InputStream): List<String> {
    val sb = StringBuilder()
    var last4 = 0
    while (true) {
        val b = input.read()
        if (b == -1) break
        sb.append(b.toChar())
        if (sb.length > MAX_HEADER_BYTES) throw IOException("Response headers exceed $MAX_HEADER_BYTES bytes")
        last4 = (last4 shl 8) or b
        if (last4 == 0x0D0A0D0A) break
    }
    return sb.toString().trim().split("\r\n")
}

/** Reads a single CRLF-terminated line (chunk-size lines and chunk trailers). */
private fun readChunkedLine(input: InputStream): String {
    val sb = StringBuilder()
    while (true) {
        val b = input.read()
        if (b == -1) break // stream ended mid-line; the caller fails on the malformed size
        if (b == '\r'.code) continue
        if (b == '\n'.code) break
        sb.append(b.toChar())
    }
    return sb.toString()
}

/**
 * Decodes an HTTP/1.1 "Transfer-Encoding: chunked" body. Each chunk is a hex size line (optionally with
 * ";extension", which is ignored), the chunk data, and a CRLF. A zero-size chunk ends the body and may be
 * followed by trailer headers.
 *
 * [onChunk] receives a shared buffer and the number of valid bytes in it. Returns the total decoded length.
 */
private fun readChunkedBody(input: InputStream, onChunk: (buf: ByteArray, n: Int) -> Unit): Long {
    var total = 0L
    val buffer = ByteArray(8192)
    while (true) {
        val sizeLine = readChunkedLine(input).substringBefore(';').trim()
        val chunkSize = sizeLine.toIntOrNull(16)
            ?: throw IOException("Malformed chunk size line: '$sizeLine'")

        if (chunkSize == 0) {
            while (readChunkedLine(input).isNotEmpty()) { /* discard trailer headers */ }
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
        readChunkedLine(input) // CRLF after each chunk's data
    }
    return total
}

/** Reads the whole body, decoding chunked transfer encoding when the server uses it. */
private fun readBodyBytes(input: InputStream, headers: List<String>): ByteArray =
    if (isChunked(headers)) {
        val out = ByteArrayOutputStream()
        readChunkedBody(input) { buf, n -> out.write(buf, 0, n) }
        out.toByteArray()
    } else {
        input.readBytes()
    }

private class RawResponse(
    val statusLine: String,
    val statusCode: Int,
    val location: String?,
    val headers: List<String>,
    val body: ByteArray
) {
    /** Status line, headers and decoded body, as text. */
    fun text(): String = headers.joinToString("\r\n") + "\r\n\r\n" + String(body, Charsets.UTF_8)
}

object InternetAPI {
    private var defaultDns: DnsStrategy = DnsStrategy.System

    /** Resolvers queried directly over UDP, in order, only after the system resolver fails. */
    private val fallbackDnsServers = listOf("1.1.1.1", "8.8.8.8")

    fun setDefaultDns(strategy: DnsStrategy) {
        defaultDns = strategy
    }

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
            throw Exception(
                "System DNS failed for $domain. Fallbacks also failed: ${fallbackErrors.joinToString(", ")}",
                systemFailure
            )
        }
    }

    suspend fun openSocket(config: SocketConfig): BaseSocket = withContext(Dispatchers.IO) {
        val host = config.address
            .removePrefix("http://")
            .removePrefix("https://")
            .substringBefore("/")
            .substringBefore(":")
        val proxy = config.proxy

        if (host.endsWith(".onion") && proxy !is ProxyConfig.Socks5) {
            throw IllegalArgumentException(".onion addresses require a SOCKS5 proxy")
        }

        if (config.protocol == TransportProtocol.UDP) {
            if (proxy is ProxyConfig.Socks5) {
                throw UnsupportedOperationException("UDP via SOCKS5 proxy is currently not supported")
            }
            if (config.useSSL) {
                throw IllegalArgumentException("SSL/TLS is not supported for plain UDP sockets")
            }
            val address = InetAddress.getByName(resolve(host))
            val socket = DatagramSocket()
            try {
                return@withContext UdpSocketWrapper(socket, address, config.port, config.timeoutMs)
            } catch (e: Exception) {
                socket.close()
                throw e
            }
        }

        val socket = Socket()
        try {
            // Set before connecting so the SOCKS5 handshake and every later read are time-bounded too.
            socket.soTimeout = config.timeoutMs

            when (proxy) {
                is ProxyConfig.Socks5 -> {
                    socket.connect(InetSocketAddress(proxy.host, proxy.port), config.timeoutMs)
                    // The hostname goes to the proxy unresolved, so the lookup does not leak locally.
                    Socks5Handler.performHandshake(socket, host, config.port)
                }
                ProxyConfig.None -> {
                    socket.connect(InetSocketAddress(resolve(host), config.port), config.timeoutMs)
                }
            }

            if (config.useSSL) {
                val ssl = (SSLSocketFactory.getDefault() as SSLSocketFactory)
                    .createSocket(socket, host, config.port, true) as SSLSocket
                try {
                    ssl.soTimeout = config.timeoutMs
                    ssl.startHandshake()
                    if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(host, ssl.session)) {
                        throw IOException("Hostname verification failed for $host")
                    }
                } catch (e: Exception) {
                    ssl.close()
                    throw e
                }
                TcpSocketWrapper(ssl)
            } else {
                TcpSocketWrapper(socket)
            }
        } catch (e: Exception) {
            socket.close()
            throw e
        }
    }

    /**
     * Downloads a file over HTTP or HTTPS.
     *
     * @param url Download target URL.
     * @param destinationFile Local destination. Parent directories are created if needed.
     * @param followRedirects Whether 3xx redirects are followed.
     * @param maxRedirects Maximum number of redirects to follow.
     * @param proxy Proxy configuration.
     * @param onProgress Called with (bytesDownloaded, totalBytes); totalBytes is -1 when unknown.
     */
    suspend fun downloadFile(
        url: String,
        destinationFile: File,
        followRedirects: Boolean = true,
        maxRedirects: Int = 5,
        proxy: ProxyConfig = ProxyConfig.None,
        onProgress: ((bytesDownloaded: Long, totalBytes: Long) -> Unit)? = null
    ): Result<File> = withContext(Dispatchers.IO) {
        try {
            var currentUrl = url
            for (hop in 0..maxRedirects) {
                val target = parseHttpUrl(currentUrl)
                val socket = openSocket(
                    SocketConfig(target.host, target.port, TransportProtocol.TCP, proxy, useSSL = target.https)
                )
                var nextUrl: String? = null
                try {
                    socket.write(httpRequest("GET", target))
                    val input = socket.getInputStream()
                    val headers = readHeaders(input)
                    val statusLine = headers.firstOrNull() ?: throw IOException("Empty response from server")
                    val statusCode = parseStatusCode(statusLine)

                    if (followRedirects && statusCode in 300..399) {
                        val location = headerValue(headers, "Location")
                            ?: throw IOException("Redirect $statusCode received without Location header")
                        nextUrl = URI(currentUrl).resolve(location).toString()
                    } else {
                        if (statusCode !in 200..299) throw IOException("HTTP error $statusCode: $statusLine")

                        val contentLength = headerValue(headers, "Content-Length")?.toLongOrNull() ?: -1L
                        val chunked = isChunked(headers)
                        destinationFile.parentFile?.mkdirs()

                        var totalRead = 0L
                        FileOutputStream(destinationFile).use { out ->
                            if (chunked) {
                                readChunkedBody(input) { buf, n ->
                                    out.write(buf, 0, n)
                                    totalRead += n
                                    onProgress?.invoke(totalRead, -1L)
                                }
                            } else {
                                val buffer = ByteArray(8192)
                                while (true) {
                                    val n = input.read(buffer)
                                    if (n == -1) break
                                    out.write(buffer, 0, n)
                                    totalRead += n
                                    onProgress?.invoke(totalRead, contentLength)
                                }
                            }
                        }

                        // A dropped connection looks like a clean end of stream, so check the length ourselves.
                        if (contentLength >= 0 && totalRead != contentLength) {
                            destinationFile.delete()
                            throw IOException("Incomplete download: got $totalRead of $contentLength bytes")
                        }
                        return@withContext Result.success(destinationFile)
                    }
                } finally {
                    socket.close()
                }
                currentUrl = nextUrl ?: throw IOException("Redirect without a target")
            }
            Result.failure(IOException("Exceeded maximum redirect count of $maxRedirects"))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    private suspend fun exchange(
        method: String,
        target: HttpTarget,
        proxy: ProxyConfig,
        body: ByteArray? = null
    ): RawResponse {
        val socket = openSocket(SocketConfig(target.host, target.port, TransportProtocol.TCP, proxy, useSSL = target.https))
        try {
            socket.write(httpRequest(method, target, body))
            val input = socket.getInputStream()
            val headers = readHeaders(input)
            val statusLine = headers.firstOrNull() ?: throw IOException("Empty response from server")
            val bodyBytes = readBodyBytes(input, headers)
            return RawResponse(
                statusLine = statusLine,
                statusCode = parseStatusCode(statusLine),
                location = headerValue(headers, "Location"),
                headers = headers,
                body = bodyBytes
            )
        } finally {
            socket.close()
        }
    }

    /** Performs an HTTP GET and returns the body as a String. Throws if the status is not 2xx. */
    suspend fun fetchString(url: String, proxy: ProxyConfig = ProxyConfig.None): String = withContext(Dispatchers.IO) {
        val response = exchange("GET", parseHttpUrl(url), proxy)
        if (response.statusCode !in 200..299) {
            throw IOException("HTTP ${response.statusCode}: ${response.statusLine}")
        }
        String(response.body, Charsets.UTF_8)
    }

    /**
     * Performs an HTTP GET and returns the transcript: the redirect history, then the final raw response
     * (status line, headers and decoded body).
     */
    suspend fun httpGet(
        url: String,
        followRedirects: Boolean = true,
        maxRedirects: Int = 5,
        proxy: ProxyConfig = ProxyConfig.None
    ): Result<String> = withContext(Dispatchers.IO) {
        val history = StringBuilder()
        try {
            var currentUrl = url
            for (i in 0..maxRedirects) {
                history.append("--> Requesting: $currentUrl\n")
                val response = exchange("GET", parseHttpUrl(currentUrl), proxy)
                val location = response.location
                if (followRedirects && response.statusCode in 300..399 && location != null) {
                    history.append("Redirect ${response.statusCode} to: $location\n")
                    currentUrl = URI(currentUrl).resolve(location).toString()
                    continue
                }
                return@withContext Result.success("${history}\nFinal Response:\n${response.text()}")
            }
            Result.failure(IOException("${history}Too many redirects: $maxRedirects"))
        } catch (e: Exception) {
            Result.failure(Exception("${history}Error: ${e.message}", e))
        }
    }

    /** Sends a JSON POST and returns the raw response (status line, headers and decoded body). */
    suspend fun httpPost(
        url: String,
        jsonBody: String,
        proxy: ProxyConfig = ProxyConfig.None
    ): Result<String> = withContext(Dispatchers.IO) {
        try {
            val response = exchange("POST", parseHttpUrl(url), proxy, jsonBody.toByteArray(Charsets.UTF_8))
            Result.success(response.text())
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
        if (bytesRead == -1) byteArrayOf() else buffer.copyOfRange(0, bytesRead)
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
        socket.send(DatagramPacket(data, data.size, remoteAddress, remotePort))
    }

    /** Throws (e.g. SocketTimeoutException) on failure, so an empty result always means an empty datagram. */
    override suspend fun read(bufferSize: Int): ByteArray = withContext(Dispatchers.IO) {
        val buffer = ByteArray(bufferSize)
        val packet = DatagramPacket(buffer, buffer.size)
        socket.receive(packet)
        buffer.copyOfRange(0, packet.length)
    }

    override suspend fun readFully(): ByteArray = read(65535)

    override fun close() {
        socket.close()
    }
}
