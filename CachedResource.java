package CSE471;

import java.io.*;
import java.net.URL;
import java.nio.file.*;

public class CachedResource {
    private URL url;
    private String filePath;
    private long timestamp;

    public CachedResource(URL url, String filePath, long timestamp) {
        this.url = url;
        this.filePath = filePath;
        this.timestamp = timestamp;
    }

    public URL getUrl() {
        return url;
    }

    public String getFilePath() {
        return filePath;
    }

    public boolean isExpired() {
        long duration = System.currentTimeMillis() - timestamp;
        return duration > 300000; // 5 minutes expiration
    }

    public byte[] getData() throws IOException {
        Path path = Paths.get(filePath);
        if (!Files.exists(path)) {
            throw new FileNotFoundException("Cache file not found: " + filePath);
        }
        return Files.readAllBytes(path);
    }

    public void setData(byte[] data) throws IOException {
        Files.createDirectories(Paths.get(filePath).getParent());
        Files.write(Paths.get(filePath), data);
    }
}



