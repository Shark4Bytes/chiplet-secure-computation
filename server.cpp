// server2.cpp - simple bidirectional TCP server
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>

static bool send_all(int fd, const std::string &data) {
    size_t total = 0;
    while (total < data.size()) {
        ssize_t sent = send(fd, data.data() + total, data.size() - total, 0);
        if (sent <= 0) return false;
        total += static_cast<size_t>(sent);
    }
    return true;
}

int main(int argc, char **argv) {
    // Require bind IP argument; show usage and exit when none provided
    if (argc < 2) {
        std::cout << "Usage: server <bind_ip> [port]\n";
        return 0;
    }

    if (std::string(argv[1]) == "-h" || std::string(argv[1]) == "--help") {
        std::cout << "Usage: server <bind_ip> [port]\n";
        return 0;
    }

    const char *bind_ip = argv[1];
    int port = 12345;
    if (argc >= 3) {
        try { port = std::stoi(argv[2]); }
        catch (...) { std::cerr << "Invalid port, using default 12345\n"; }
    }

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) { std::cerr << "socket() failed: " << strerror(errno) << '\n'; return 1; }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    if (std::string(bind_ip) == "0.0.0.0") {
        addr.sin_addr.s_addr = INADDR_ANY;
    } else if (inet_pton(AF_INET, bind_ip, &addr.sin_addr) <= 0) {
        std::cerr << "Invalid bind IP: " << bind_ip << '\n';
        close(listen_fd);
        return 1;
    }
    addr.sin_port = htons(static_cast<uint16_t>(port));

    if (bind(listen_fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "bind() failed: " << strerror(errno) << '\n';
        close(listen_fd);
        return 1;
    }

    if (listen(listen_fd, 1) < 0) {
        std::cerr << "listen() failed: " << strerror(errno) << '\n';
        close(listen_fd);
        return 1;
    }

    std::cout << "Server listening on port " << port << "..." << std::endl;

    sockaddr_in peer_addr{};
    socklen_t peer_len = sizeof(peer_addr);
    int conn_fd = accept(listen_fd, (sockaddr*)&peer_addr, &peer_len);
    if (conn_fd < 0) {
        std::cerr << "accept() failed: " << strerror(errno) << '\n';
        close(listen_fd);
        return 1;
    }

    char peer_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &peer_addr.sin_addr, peer_ip, sizeof(peer_ip));
    std::cout << "Connection from " << peer_ip << ":" << ntohs(peer_addr.sin_port) << '\n';

    std::atomic<bool> running{true};

    // Receiver thread
    std::thread receiver([&]() {
        std::string buffer;
        char tmp[512];
        while (running) {
            ssize_t r = recv(conn_fd, tmp, sizeof(tmp), 0);
            if (r == 0) {
                std::cout << "Peer closed connection." << std::endl;
                running = false;
                break;
            }
            if (r < 0) {
                std::cerr << "recv() failed: " << strerror(errno) << '\n';
                running = false;
                break;
            }
            buffer.append(tmp, tmp + r);
            // split by newline
            size_t pos;
            while ((pos = buffer.find('\n')) != std::string::npos) {
                std::string line = buffer.substr(0, pos);
                buffer.erase(0, pos + 1);
                std::cout << "received: {" << line << "}" << std::endl;
            }
        }
    });

    // Sender thread (reads stdin)
    std::thread sender([&]() {
        std::string line;
        while (running && std::getline(std::cin, line)) {
            if (!send_all(conn_fd, line + "\n")) {
                std::cerr << "send() failed or peer closed." << std::endl;
                running = false;
                break;
            }
        }
        running = false;
        shutdown(conn_fd, SHUT_WR);
    });

    sender.join();
    receiver.join();

    close(conn_fd);
    close(listen_fd);
    return 0;
}
