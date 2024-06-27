### Proxy Server

![image](https://github.com/Pegasushi30/Proxy-Project/assets/121224269/7cd1e025-7e9b-4865-9fbe-acb6eb93b405)

## Overview

The Java Proxy Server project is a sophisticated, multi-functional proxy server designed for educational purposes, specifically for the CSE471 Data Communications and Computer Networks course at Yeditepe University. The project implements various features such as handling HTTP and HTTPS requests, caching, logging, and filtering based on client tokens. It provides a practical understanding of network communications, socket programming, and HTTP protocol intricacies.

## Features

### 1. HTTP and HTTPS Requests Handling
- The proxy server efficiently handles both HTTP and HTTPS requests, ensuring secure communication between clients and servers.
- Supports various HTTP methods including GET, HEAD, POST, OPTIONS, and CONNECT.

### 2. Caching
- Implements a caching mechanism to store frequently accessed resources, reducing the load on destination servers and improving response times.
- Supports caching based on 'Last-Modified' headers and handles large file downloads (>500 MB).

### 3. Logging
- Detailed logging of client requests, including request type, timestamp, and destination server.
- Generates reports on client request logs for analysis and troubleshooting.

### 4. Filtering
- Implements web filtering based on client tokens. Clients are prompted with a simple login page to enter a token, which determines their access level.
- Filters requests to blocked hosts and sends a custom "host is blocked" message.

### 5. Thread Safety and Socket Management
- Improved thread safety and socket-stream usage in the ServerHandler class to ensure stable and efficient handling of multiple client connections simultaneously.

## Class Structure

### ProxyServer
- Manages client connections and delegates request handling to ServerHandler instances.
- Starts and stops the server and generates reports on client request logs.

### ServerHandler
- Processes various HTTP requests and manages caching, logging, and filtering functionalities.
- Handles blocked hosts and sends custom messages for blocked requests.

### RequestLogEntry
- Represents individual log entries for client requests, used for generating detailed logs and reports.

### CachedResource
- Represents cached resources, including metadata for cache management.

### TransparentProxyGUI
- Provides a graphical user interface for monitoring and controlling the proxy server.

### HttpMethods
- Defines and manages various HTTP methods supported by the server.

