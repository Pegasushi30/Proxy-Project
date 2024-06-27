package CSE471;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.Socket;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import javax.swing.JTextArea;

public class ServerHandler extends Thread {
    private Socket clientSocket;
    private JTextArea displayArea;
    private Set<String> blockedHosts;
    private Map<String, CachedResource> cache;

    private ConcurrentLinkedQueue<RequestLogEntry> requestLogs;
    private static final int MAX_FILE_SIZE = 500 * 1024 * 1024; // 500 MB
    private static final int BUFFER_SIZE = 8192; // 8 KB
    private static final String LOGIN_PAGE = "<html><body><h2>Login Page</h2><form method='post'>Token: <input type='text' name='token'><input type='submit' value='Submit'></form></body></html>";
    private static final Map<String, Boolean> clientTokens = new ConcurrentHashMap<>();

    public ServerHandler(Socket clientSocket, JTextArea displayArea, Set<String> blockedHosts,
                         Map<String, CachedResource> cache, ConcurrentLinkedQueue<RequestLogEntry> requestLogs) {
        this.clientSocket = clientSocket;
        this.displayArea = displayArea;
        this.blockedHosts = blockedHosts;
        this.cache = cache;
        this.requestLogs = requestLogs;
    }

    @Override
    public void run() {
        try {
            BufferedReader clientInput = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            OutputStream clientOutput = clientSocket.getOutputStream();
            String clientIP = clientSocket.getInetAddress().getHostAddress();

            if (!clientTokens.containsKey(clientIP)) {
                String requestLine = clientInput.readLine();
                String[] tokens = requestLine.split(" ");
                String method = tokens[0];
                if (HttpMethods.POST.equalsIgnoreCase(method)) {
                    handleTokenSubmission(clientInput, clientOutput, clientIP);
                    return;
                } else {
                    serveLoginPage(clientOutput);
                    return;
                }
            }

            String clientDetails = "Connection from: " + clientIP + ", Port: " + clientSocket.getPort();
            displayArea.append(clientDetails + "\n");

            String requestLine = clientInput.readLine();
            if (requestLine == null || requestLine.isEmpty()) {
                sendBadRequest(clientOutput);
                return;
            }

            String[] tokens = requestLine.split(" ");
            if (tokens.length < 2) {
                sendBadRequest(clientOutput);
                return;
            }

            String method = tokens[0];
            String hostAndPort = tokens[1];
            boolean isFilteringEnabled = clientTokens.get(clientIP);

            if (HttpMethods.GET1.equalsIgnoreCase(method)) {
                displayArea.append("Processing HTTP request for " + hostAndPort + " from IP: " + clientIP + "\n");
                handleHTTPSRequest(hostAndPort, clientOutput, isFilteringEnabled);
                return;
            } else {
                displayArea.append("Processing HTTP request: " + method + " " + tokens[1] + " from IP: " + clientIP + "\n");
            }

            URL url = new URL(tokens[1]);
            if (isFilteringEnabled && blockedHosts.contains(url.getHost())) {
                sendBlockedHostMessage(clientOutput);
                return;
            }

            logRequest(url.getHost(), url.getFile(), method, 200);

            switch (method.toUpperCase()) {
                case HttpMethods.GET:
                    handleGET_HEAD(clientOutput, url, HttpMethods.GET);
                    break;
                case HttpMethods.HEAD:
                    handleGET_HEAD(clientOutput, url, HttpMethods.HEAD);
                    break;
                case HttpMethods.POST:
                    handlePostRequest(clientInput, clientOutput, url);
                    break;
                case HttpMethods.OPTIONS:
                    handleOptionsRequest(clientOutput, url);
                    break;
                default:
                    sendBadRequest(clientOutput);
                    break;
            }
        } catch (IOException e) {
            displayArea.append("Error processing request: " + e.getMessage() + "\n");
        } finally {
            closeResources();
        }
    }

    private void handleHTTPSRequest(String hostAndPort, OutputStream clientOutput, boolean isFilteringEnabled) throws IOException {
        String[] parts = hostAndPort.split(":");
        String host = parts[0];
        int port = (parts.length > 1) ? Integer.parseInt(parts[1]) : 443;  // Default HTTPS port is 443

        if (isFilteringEnabled && blockedHosts.contains(host)) {
            sendBlockedHostMessage(clientOutput);
            return;
        }

        try (Socket remoteSocket = new Socket(host, port);
             InputStream remoteInput = remoteSocket.getInputStream();
             OutputStream remoteOutput = remoteSocket.getOutputStream();
             InputStream clientInput = clientSocket.getInputStream()) {

            // Inform the client that a tunnel has been established
            PrintWriter out = new PrintWriter(clientOutput, true);
            out.print("HTTP/1.1 200 Connection Established\r\n");
            out.print("Proxy-Agent: CustomProxy/1.0\r\n");
            out.print("\r\n");
            out.flush();

            // Read the initial part of the TLS handshake to get the ClientHello message
            byte[] clientHello = new byte[4096];
            int bytesRead = clientInput.read(clientHello);
            if (bytesRead == -1) {
                throw new IOException("Failed to read ClientHello message from client");
            }

            // Extract SNI from the ClientHello message
            String sniHost = getSNIHost(clientHello, bytesRead);
            if (sniHost != null) {
                displayArea.append("Extracted SNI host: " + sniHost + "\n");
                // Check if the SNI host is blocked
                if (isFilteringEnabled && blockedHosts.contains(sniHost)) {
                    sendBlockedHostMessage(clientOutput);
                    return;
                }
            }

            // Relay the initial ClientHello message to the remote server
            remoteOutput.write(clientHello, 0, bytesRead);
            remoteOutput.flush();

            // Relay traffic
            Thread clientToRemote = new Thread(() -> {
                try {
                    relayData(clientInput, remoteOutput);
                } catch (IOException e) {
                    displayArea.append("Error relaying data from client to remote: " + e.getMessage() + "\n");
                }
            });
            Thread remoteToClient = new Thread(() -> {
                try {
                    relayData(remoteInput, clientOutput);
                } catch (IOException e) {
                    displayArea.append("Error relaying data from remote to client: " + e.getMessage() + "\n");
                }
            });
            clientToRemote.start();
            remoteToClient.start();

            try {
                clientToRemote.join();  // Wait for completion of forward thread
                remoteToClient.join();  // Wait for completion of backward thread
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();  // Handle interrupts properly
            }
        } catch (IOException e) {
            displayArea.append("Error setting up CONNECT request: " + e.getMessage() + "\n");
            sendBadRequest(clientOutput);
        }
    }

    private String getSNIHost(byte[] clientHello, int length) {
        int position = 0;
        while (position < length - 4) {
            // Look for the SNI extension (0x00 0x00)
            if ((clientHello[position] & 0xFF) == 0x00 && (clientHello[position + 1] & 0xFF) == 0x00) {
                // Skip the next 5 bytes (extension type and length)
                position += 5;
                // Ensure we don't go out of bounds
                if (position + 2 > length) {
                    return null;
                }
                // The next byte indicates the type of name (0x00 for host)
                if ((clientHello[position] & 0xFF) == 0x00) {
                    // Ensure we don't go out of bounds
                    if (position + 3 > length) {
                        return null;
                    }
                    // The next 2 bytes indicate the length of the hostname
                    int hostLength = (clientHello[position + 1] & 0xFF) << 8 | (clientHello[position + 2] & 0xFF);
                    position += 3;
                    // Ensure we don't go out of bounds
                    if (position + hostLength > length) {
                        return null;
                    }
                    // Extract the hostname
                    return new String(clientHello, position, hostLength);
                }
            }
            position++;
        }
        return null;
    }

    private void relayData(InputStream in, OutputStream out) throws IOException {
        byte[] buffer = new byte[BUFFER_SIZE];
        int read;
        while ((read = in.read(buffer)) != -1) {
            out.write(buffer, 0, read);
            out.flush();
        }
    }

    private void serveLoginPage(OutputStream clientOutput) throws IOException {
        PrintWriter out = new PrintWriter(clientOutput, true);
        out.print("HTTP/1.1 200 OK\r\n");
        out.print("Content-Type: text/html\r\n");
        out.print("Content-Length: " + LOGIN_PAGE.length() + "\r\n");
        out.print("\r\n");
        out.print(LOGIN_PAGE);
        out.flush();
    }

    private void handleTokenSubmission(BufferedReader clientInput, OutputStream clientOutput, String clientIP) throws IOException {
        StringBuilder requestBody = new StringBuilder();
        while (!clientInput.readLine().isEmpty()) {
            // Read headers
        }
        while (clientInput.ready()) {
            requestBody.append((char) clientInput.read());
        }

        String token = extractTokenFromRequestBody(requestBody.toString());
        if (validateToken(token)) {
            boolean isFilteringEnabled = "51e2cba401".equals(token);
            clientTokens.put(clientIP, isFilteringEnabled);
            displayArea.append("Token validated for IP: " + clientIP + "\n");
            serveSuccessPage(clientOutput);
        } else {
            displayArea.append("Invalid token for IP: " + clientIP + "\n");
            serveLoginPage(clientOutput);
        }
    }

    private String extractTokenFromRequestBody(String requestBody) {
        for (String param : requestBody.split("&")) {
            String[] pair = param.split("=");
            if (pair.length == 2 && "token".equals(pair[0])) {
                return pair[1];
            }
        }
        return null;
    }

    private boolean validateToken(String token) {
        return "8a21bce200".equals(token) || "51e2cba401".equals(token);
    }

    private void serveSuccessPage(OutputStream clientOutput) throws IOException {
        String successPage = "<html><body><h2>Token accepted. You can now access the internet.</h2></body></html>";
        PrintWriter out = new PrintWriter(clientOutput, true);
        out.print("HTTP/1.1 200 OK\r\n");
        out.print("Content-Type: text/html\r\n");
        out.print("Content-Length: " + successPage.length() + "\r\n");
        out.print("\r\n");
        out.print(successPage);
        out.flush();
    }

    private void handleGET_HEAD(OutputStream clientOutput, URL url, String method) throws IOException {
        String urlString = url.toString();
        String cacheKey = "cache/" + sanitizeFilePath(urlString) + ".cache";

        if (cache.containsKey(urlString)) {
            CachedResource resource = cache.get(urlString);
            if (!resource.isExpired()) {
                try {
                    byte[] data = resource.getData();
                    clientOutput.write(data);
                    clientOutput.flush();
                    logCachedDataSent(urlString, clientSocket.getInetAddress().getHostAddress());
                    return;
                } catch (IOException e) {
                    displayArea.append("Failed to read cache for URL: " + urlString + "\n");
                    e.printStackTrace();
                }
            } else {
                displayArea.append("Cache expired for URL: " + urlString + "\n");
            }
        } else {
            displayArea.append("No cache entry found for URL: " + urlString + ". Fetching from server...\n");
        }

        if (method.equals("GET")) {
            if (url.openConnection() instanceof HttpURLConnection) {
                HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                connection.setRequestMethod("GET");
                connection.connect();
                int contentLength = connection.getContentLength();
                connection.disconnect();

                if (contentLength > MAX_FILE_SIZE) {
                    sendBadRequest(clientOutput);
                    return;
                }
            }
        }

        fetchAndCacheGET_HEAD(url, method, clientOutput, urlString, cacheKey);
    }

    private void fetchAndCacheGET_HEAD(URL url, String method, OutputStream clientOutput, String urlString, String cacheKey) throws IOException {
        ByteArrayOutputStream bufferStream = new ByteArrayOutputStream();
        String sanitizedCacheKey = sanitizeFilePath(cacheKey);
        Path cacheFilePath = Paths.get("cache", sanitizedCacheKey);

        try (Socket socket = new Socket(url.getHost(), url.getPort() == -1 ? url.getDefaultPort() : url.getPort());
             InputStream serverInput = socket.getInputStream();
             OutputStream serverOutput = socket.getOutputStream();
             PrintWriter writer = new PrintWriter(serverOutput, true)) {

            writer.println(method + " " + url.getFile() + " HTTP/1.1");
            writer.println("Host: " + url.getHost());
            writer.println("Connection: close");
            writer.println();

            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = serverInput.read(buffer)) != -1) {
                bufferStream.write(buffer, 0, bytesRead);
            }
            byte[] data = bufferStream.toByteArray();
            clientOutput.write(data);
            clientOutput.flush();

            Files.createDirectories(cacheFilePath.getParent());
            Files.write(cacheFilePath, data);
            cache.put(urlString, new CachedResource(url, cacheFilePath.toString(), System.currentTimeMillis()));
            displayArea.append("New data fetched and cached for URL: " + urlString + "\n");
        }
    }

    private void handlePostRequest(BufferedReader clientInput, OutputStream clientOutput, URL url) throws IOException {
        List<String> headers = new ArrayList<>();
        StringBuilder bodyBuilder = new StringBuilder();
        String contentLength = "0";
        String line;
        while (!(line = clientInput.readLine()).isEmpty()) {
            headers.add(line);
            if (line.startsWith("Content-Length:")) {
                contentLength = line.split(":")[1].trim();
            }
        }

        if (Integer.parseInt(contentLength) > MAX_FILE_SIZE) {
            displayArea.append("POST request failed for domain: " + url.toString() + "; Content-Length exceeds limit.\n");
            sendBadRequest(clientOutput);
            return;
        }

        int length = Integer.parseInt(contentLength);
        char[] body = new char[length];
        clientInput.read(body, 0, length);
        bodyBuilder.append(body);

        String urlString = url.toString();
        String cacheKey = "cache/" + urlString.replaceAll("[:/]", "_") + ".cache";

        fetchAndCachePOST(clientOutput, url, "POST", urlString, headers, bodyBuilder.toString(), cacheKey);
    }

    private void fetchAndCachePOST(OutputStream clientOutput, URL url, String method, String urlString, List<String> headers, String requestBody, String cacheKey) throws IOException {
        String sanitizedCacheKey = sanitizeFilePath(cacheKey);
        Path cacheFilePath = Paths.get("cache", sanitizedCacheKey);

        if (cache.containsKey(urlString)) {
            CachedResource resource = cache.get(urlString);
            if (!resource.isExpired()) {
                try {
                    byte[] data = resource.getData();
                    clientOutput.write(data);
                    clientOutput.flush();
                    displayArea.append("Cache hit for " + urlString + "\n");
                    return;
                } catch (IOException e) {
                    displayArea.append("Failed to read cache for URL: " + urlString + "\n");
                }
            } else {
                displayArea.append("Cache expired for URL: " + urlString + "\n");
            }
        } else {
            displayArea.append("No cache entry found for URL: " + urlString + ". Fetching from server...\n");
        }

        ByteArrayOutputStream bufferStream = new ByteArrayOutputStream();
        try (Socket socket = new Socket(url.getHost(), url.getPort() == -1 ? url.getDefaultPort() : url.getPort());
             InputStream serverInput = socket.getInputStream();
             OutputStream serverOutput = socket.getOutputStream();
             PrintWriter writer = new PrintWriter(serverOutput, true)) {

            writer.println(method + " " + url.getFile() + " HTTP/1.1");
            writer.println("Host: " + url.getHost());
            writer.println("Connection: close");
            headers.forEach(header -> writer.println(header));
            writer.println(); // End of headers
            writer.print(requestBody);
            writer.flush();

            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = serverInput.read(buffer)) != -1) {
                bufferStream.write(buffer, 0, bytesRead);
            }
            byte[] data = bufferStream.toByteArray();
            clientOutput.write(data);
            clientOutput.flush();

            Files.createDirectories(cacheFilePath.getParent());
            Files.write(cacheFilePath, data);
            cache.put(urlString, new CachedResource(url, cacheFilePath.toString(), System.currentTimeMillis()));
            displayArea.append("New data fetched and cached for URL: " + urlString + "\n");
        }
    }

    private void handleOptionsRequest(OutputStream clientOutput, URL url) throws IOException {
        String urlString = url.toString();
        String cacheKey = "cache/" + urlString.replaceAll("[:/]", "_") + ".cache";
        if (cache.containsKey(urlString) && !cache.get(urlString).isExpired()) {
            byte[] data = cache.get(urlString).getData();
            clientOutput.write(data);
            clientOutput.flush();
            logCachedDataSent(urlString, clientSocket.getInetAddress().getHostAddress());
            return;
        }

        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("OPTIONS");
        connection.connect();
        String allowHeader = connection.getHeaderField("Allow");

        ByteArrayOutputStream bufferStream = new ByteArrayOutputStream();
        bufferStream.write(("HTTP/1.1 204 No Content\r\nAllow: " + allowHeader + "\r\nConnection: close\r\n\r\n").getBytes());
        byte[] response = bufferStream.toByteArray();

        clientOutput.write(response);
        clientOutput.flush();
        connection.disconnect();

        Files.createDirectories(Paths.get("cache"));
        Files.write(Paths.get(sanitizeFilePath(cacheKey)), response);
        cache.put(urlString, new CachedResource(url, sanitizeFilePath(cacheKey), System.currentTimeMillis()));
        displayArea.append("No cache entry found for URL: " + urlString + ". Fetching from server...\n");
    }

    private void logRequest(String domain, String resourcePath, String method, int statusCode) {
        RequestLogEntry entry = new RequestLogEntry(new Date(), clientSocket.getInetAddress().getHostAddress(), domain, resourcePath, method, statusCode);
        requestLogs.add(entry);
        displayArea.append("Logged request: " + method + " " + domain + resourcePath + "\n");
    }

    private void logCachedDataSent(String url, String clientIP) {
        String urlString = url.toString();
        displayArea.append("Cache hit for URL: " + urlString + "\n");
    }

    private void sendBadRequest(OutputStream clientOutput) throws IOException {
        String response = "HTTP/1.1 400 Bad Request\r\n\r\n";
        clientOutput.write(response.getBytes());
        clientOutput.flush();
    }

    private void sendBlockedHostMessage(OutputStream clientOutput) throws IOException {
        String response = "HTTP/1.1 403 Forbidden\r\n\r\nHost is blocked.";
        clientOutput.write(response.getBytes());
        clientOutput.flush();
    }

    private void closeResources() {
        try {
            if (clientSocket != null && !clientSocket.isClosed()) {
                clientSocket.close();
            }
        } catch (IOException e) {
            displayArea.append("Failed to close resources: " + e.getMessage() + "\n");
        }
    }

    private String sanitizeFilePath(String filePath) {
        return filePath.replaceAll("[^a-zA-Z0-9\\-_\\.]", "_");
    }
}