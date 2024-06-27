package CSE471;
import javax.swing.*;
import java.awt.*;
import java.util.*;

public class TransparentProxyGUI extends JFrame {
    private static final long serialVersionUID = 1L;
    private JTextArea displayArea;
    private Set<String> blockedHosts = new HashSet<>();
    private ProxyServer proxyServer;
    private Map<String, CachedResource> cache = new HashMap<>();

    public TransparentProxyGUI() {
        setTitle("Transparent Proxy Application");
        setSize(600, 400);
        setLocationRelativeTo(null);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        initGUI();
    }

    private void initGUI() {
        JMenuBar menuBar = new JMenuBar();
        JMenu fileMenu = new JMenu("File");
        JMenuItem startItem = new JMenuItem("Start");
        JMenuItem stopItem = new JMenuItem("Stop");
        JMenuItem reportItem = new JMenuItem("Report");
        JMenuItem addHostItem = new JMenuItem("Add host to filter");
        JMenuItem removeHostItem = new JMenuItem("Remove host filter");
        JMenuItem displayHostsItem = new JMenuItem("Display current filtered hosts");
        JMenuItem exitItem = new JMenuItem("Exit");

        startItem.addActionListener(e -> startProxy());
        stopItem.addActionListener(e -> stopProxy());
        reportItem.addActionListener(e -> showReportDialog());
        addHostItem.addActionListener(e -> addHost());
        removeHostItem.addActionListener(e -> removeHost());
        displayHostsItem.addActionListener(e -> displayHosts());
        exitItem.addActionListener(e -> System.exit(0));

        fileMenu.add(startItem);
        fileMenu.add(stopItem);
        fileMenu.add(reportItem);
        fileMenu.addSeparator();
        fileMenu.add(addHostItem);
        fileMenu.add(removeHostItem);
        fileMenu.add(displayHostsItem);
        fileMenu.addSeparator();
        fileMenu.add(exitItem);

        JMenu helpMenu = new JMenu("Help");
        JMenuItem aboutItem = new JMenuItem("About");
        aboutItem.addActionListener(e -> showAbout());
        helpMenu.add(aboutItem);

        menuBar.add(fileMenu);
        menuBar.add(helpMenu);

        setJMenuBar(menuBar);
        displayArea = new JTextArea();
        displayArea.setEditable(false);
        Color lightBlue = new Color(173, 216, 230); // Light blue color
        displayArea.setBackground(lightBlue);
        displayArea.setFont(new Font("Arial", Font.ITALIC, 14));
        JScrollPane scrollPane = new JScrollPane(displayArea);
        add(scrollPane);
    }

    private void startProxy() {
        if (proxyServer == null || !proxyServer.isAlive()) {
            proxyServer = new ProxyServer(displayArea, blockedHosts, cache);
            proxyServer.start();
            displayArea.append("Proxy server started successfully.\n");
        } else {
            JOptionPane.showMessageDialog(this, "Proxy is already running.", "Warning", JOptionPane.WARNING_MESSAGE);
        }
    }

    private void stopProxy() {
        if (proxyServer != null && proxyServer.isAlive()) {
            proxyServer.stopServer();
            proxyServer = null;
            displayArea.append("Proxy server stopped.\n");
        } else {
            displayArea.append("Proxy is not running or is already closed.\n");
        }
    }

    private void showReportDialog() {
        String clientIP = JOptionPane.showInputDialog(this, "Enter client IP for report:");
        if (clientIP != null && !clientIP.isEmpty()) {
            proxyServer.generateReport(clientIP);
        }
    }

    private void addHost() {
        String host = JOptionPane.showInputDialog(this, "Enter host to block:");
        if (host != null && !host.isEmpty()) {
            blockedHosts.add(host);
            displayArea.append("Blocked host added: " + host + "\n");
        }
    }

    private void removeHost() {
        String host = JOptionPane.showInputDialog(this, "Enter host to remove from filter:");
        if (host != null && !host.isEmpty()) {
            if (blockedHosts.remove(host)) {
                displayArea.append("Host removed from filter: " + host + "\n");
            } else {
                displayArea.append("Host was not found in filter: " + host + "\n");
            }
        }
    }

    private void displayHosts() {
        StringBuilder sb = new StringBuilder("Blocked Hosts:\n");
        for (String host : blockedHosts) {
            sb.append(host).append("\n");
        }
        JOptionPane.showMessageDialog(this, sb.toString());
    }

    private void showAbout() {
        JOptionPane.showMessageDialog(this, "Developed by Burak Eymen Çevik");
    }

    public static void main(String[] args) {
        System.setProperty("java.net.preferIPv4Stack", "true");
        SwingUtilities.invokeLater(() -> {
            TransparentProxyGUI frame = new TransparentProxyGUI();
            frame.setVisible(true);
        });
    }
}








