package CSE471;

import java.util.Date;

public class RequestLogEntry {
    private Date date;
    private String clientIP;
    private String domain;
    private String resourcePath;
    private String method;
    private int statusCode;

    public RequestLogEntry(Date date, String clientIP, String domain, String resourcePath, String method, int statusCode) {
        this.date = date;
        this.clientIP = clientIP;
        this.domain = domain;
        this.resourcePath = resourcePath;
        this.method = method;
        this.statusCode = statusCode;
    }

    public Date getDate() {
        return date;
    }

    public String getClientIP() {
        return clientIP;
    }

    public String getDomain() {
        return domain;
    }

    public String getResourcePath() {
        return resourcePath;
    }

    public String getMethod() {
        return method;
    }

    public int getStatusCode() {
        return statusCode;
    }
}

