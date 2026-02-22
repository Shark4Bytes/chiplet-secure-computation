// client.cpp - simple bidirectional TCP client
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
    if (argc < 2) {
        std::cerr << "Usage: client <server_ip> [port]\n";
        return 1;
    }
    const char *host = argv[1];
    int port = 12345;
    if (argc >= 3) {
        port = std::stoi(argv[2]);
    } else {
        std::cout << "Enter port [12345]: ";
        std::string portline;
        if (std::getline(std::cin, portline)) {
            if (!portline.empty()) {
                try {
                    port = std::stoi(portline);
                } catch (...) {
                    std::cerr << "Invalid port input, using default 12345\n";
                }
            }
        }
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "socket() failed: " << strerror(errno) << '\n';
        return 1;
    }

    sockaddr_in serv{};
    serv.sin_family = AF_INET;
    serv.sin_port = htons(static_cast<uint16_t>(port));
    if (inet_pton(AF_INET, host, &serv.sin_addr) <= 0) {
        std::cerr << "inet_pton() failed for " << host << '\n';
        close(sock);
        return 1;
    }

    if (connect(sock, (sockaddr*)&serv, sizeof(serv)) < 0) {
        std::cerr << "connect() failed: " << strerror(errno) << '\n';
        close(sock);
        return 1;
    }

    std::cout << "Connected to " << host << ":" << port << std::endl;

    std::atomic<bool> running{true};

    std::thread receiver([&]() {
        std::string buffer;
        char tmp[512];
        while (running) {
            ssize_t r = recv(sock, tmp, sizeof(tmp), 0);
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
            size_t pos;
            while ((pos = buffer.find('\n')) != std::string::npos) {
                std::string line = buffer.substr(0, pos);
                buffer.erase(0, pos + 1);
                std::cout << "received: {" << line << "}" << std::endl;
            }
        }
    });

    std::thread sender([&]() {
        std::string line;
        while (running && std::getline(std::cin, line)) {
            if (!send_all(sock, line + "\n")) {
                std::cerr << "send() failed or peer closed." << std::endl;
                running = false;
                break;
            }
        }
        running = false;
        shutdown(sock, SHUT_WR);
    });

    sender.join();
    receiver.join();

    close(sock);
    return 0;
}