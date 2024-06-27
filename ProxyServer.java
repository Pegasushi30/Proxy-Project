package CSE471;

import java.io.*;
import java.net.*;
import java.text.SimpleDateFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import javax.swing.JOptionPane;
import javax.swing.JTextArea;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;


public class ProxyServer extends Thread {
    private ServerSocket httpServerSocket;
    private ServerSocket httpsServerSocket;
    private boolean running = true;
    private JTextArea displayArea;
    private Set<String> blockedHosts;
    private Map<String, CachedResource> cache;
    private ConcurrentLinkedQueue<RequestLogEntry> allRequestLogs = new ConcurrentLinkedQueue<>();
    private Thread httpProxyThread;
    private Thread httpsProxyThread;

    public ProxyServer(JTextArea displayArea, Set<String> blockedHosts, Map<String, CachedResource> cache) {
        this.displayArea = displayArea;
        this.blockedHosts = blockedHosts;
        this.cache = new ConcurrentHashMap<>(cache); // Ensure thread-safety
        System.setProperty("java.net.preferIPv4Stack", "true");
    }

    @Override
    public void run() {
        try {
            httpServerSocket = new ServerSocket(80);
            httpsServerSocket = new ServerSocket(443);
            displayArea.append("Proxy server started on ports 80 (HTTP) and 443 (HTTPS).\n");
            displayArea.append("Proxy Server IP Address: " + InetAddress.getLocalHost().getHostAddress() + "\n");

            // HTTP Proxy Thread
            httpProxyThread = new Thread(() -> {
                try {
                    while (running) {
                        Socket clientSocket = httpServerSocket.accept();
                        new ServerHandler(clientSocket, displayArea, blockedHosts, cache, allRequestLogs).start();
                    }
                } catch (IOException e) {
                    if (running) { // Only log unexpected errors.
                        displayArea.append("Error accepting connection on HTTP port: " + e.getMessage() + "\n");
                    }
                }
            });

            // HTTPS Proxy Thread
            httpsProxyThread = new Thread(() -> {
                try {
                    while (running) {
                        Socket clientSocket = httpsServerSocket.accept();
                        new ServerHandler(clientSocket, displayArea, blockedHosts, cache, allRequestLogs).start();
                    }
                } catch (IOException e) {
                    if (running) { // Only log unexpected errors.
                        displayArea.append("Error accepting connection on HTTPS port: " + e.getMessage() + "\n");
                    }
                }
            });

            httpProxyThread.start();
            httpsProxyThread.start();

            // Wait for both threads to finish before exiting
            try {
                httpProxyThread.join();
                httpsProxyThread.join();
            } catch (InterruptedException e) {
                displayArea.append("Proxy server interrupted: " + e.getMessage() + "\n");
                Thread.currentThread().interrupt();
            }

        } catch (IOException e) {
            displayArea.append("Could not start the proxy server on ports 80 and 443. Ports may be in use.\n" + e.getMessage() + "\n");
        } finally {
            closeServerSockets();
        }
    }

    private void closeServerSockets() {
        try {
            if (httpServerSocket != null && !httpServerSocket.isClosed()) {
                httpServerSocket.close();
            }
            if (httpsServerSocket != null && !httpsServerSocket.isClosed()) {
                httpsServerSocket.close();
            }
        } catch (IOException e) {
            displayArea.append("Error closing server sockets: " + e.getMessage() + "\n");
        }
    }

    public void stopServer() {
        running = false;
        closeServerSockets();
        if (httpProxyThread != null && httpProxyThread.isAlive()) {
            httpProxyThread.interrupt();
        }
        if (httpsProxyThread != null && httpsProxyThread.isAlive()) {
            httpsProxyThread.interrupt();
        }
    }

    private List<RequestLogEntry> getRequestLogsForClient(String clientIP) {
        return allRequestLogs.stream()
                .filter(log -> log.getClientIP().equals(clientIP))
                .collect(Collectors.toList());
    }

    public void generateReport(String clientIP) {
        List<RequestLogEntry> requestLogs = getRequestLogsForClient(clientIP);
        if (requestLogs.isEmpty()) {
            JOptionPane.showMessageDialog(null, "No data available for the IP: " + clientIP);
            return;
        }

        String folderPath = "reports/"; // Define the folder path
        File folder = new File(folderPath);
        if (!folder.exists()) {
            folder.mkdirs(); // Create the folder if it doesn't exist
        }

        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String fileName = folderPath + "report_" + clientIP + ".txt"; // Include the folder path in the file name
        try (PrintWriter writer = new PrintWriter(new FileWriter(fileName))) {
            writer.println("Date\t\tTime\t\tDomain\tResource Path\tHTTP Method\tStatus Code");
            for (RequestLogEntry entry : requestLogs) {
                writer.println(dateFormat.format(entry.getDate()) + "\t" +
                        entry.getDomain() + "\t" +
                        entry.getResourcePath() + "\t" +
                        entry.getMethod() + "\t" +
                        entry.getStatusCode());
            }
            JOptionPane.showMessageDialog(null, "Report generated successfully. Saved as " + fileName);
        } catch (IOException e) {
            JOptionPane.showMessageDialog(null, "Error occurred while writing the report: " + e.getMessage());
        }
    }
}







