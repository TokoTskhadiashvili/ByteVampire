#pragma once

#include <vector>
#include <string>
#include <regex>
#include <cstring>

#include <iostream>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#define SEND_BUFF_SIZE 1024
#define RECV_BUFF_SIZE 1024

#define SOCK_TIMEOUT_SECONDS 5

struct PortInfo {
    unsigned short port_number;
    unsigned char proto;
    bool open;

    std::string read; // Data read from the port

    std::string version;
    std::vector<std::string> cves;
};

/*
struct RemoteHost {
    std::string ip;

    std::vector<PortInfo> plain_ports;
    std::vector<PortInfo> ssl_ports;
};
*/

std::string GetServiceVersion(const std::string& read, const std::vector<std::regex>& regexes) {
    for (const std::regex& regex : regexes) {
        std::smatch match;

        if (std::regex_search(read, match, regex)) {
            return match[0].str();
        }
    }

    return "";
}

std::vector<PortInfo> ScanAddressPlainTCP(std::string& ip, std::map<unsigned short, std::string>& ports_data) {
    std::vector<PortInfo> result;

    for (const auto port_data : ports_data) {
        int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

        try {
            unsigned short port = port_data.first;
            std::string payload = port_data.second;

            sockaddr_in addr;
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

            unsigned char send_buff[SEND_BUFF_SIZE]; memset(send_buff, 0, SEND_BUFF_SIZE);
            unsigned char recv_buff[RECV_BUFF_SIZE]; memset(recv_buff, 0, RECV_BUFF_SIZE);

            int connection_result = connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
            if (connection_result < 0) {
                PortInfo port_info;
                port_info.open = false;
                port_info.port_number = port;

                result.push_back(port_info);

                close(sock);
                continue;
            }

            // Manual memcpy
            for (unsigned int i = 0; i < SEND_BUFF_SIZE && i < payload.length(); i++) {
                send_buff[i] = payload[i];
            }

            size_t data_length = std::min(static_cast<size_t>(SEND_BUFF_SIZE), payload.size());
            send(sock, send_buff, data_length, 0);
            int bytes = recv(sock, recv_buff, data_length, 0);
            if (bytes <= 0) {
                PortInfo port_info;
                port_info.open = false;
                port_info.port_number = port;

                result.push_back(port_info);

                close(sock);
                continue;
            }

            std::string received_str(reinterpret_cast<const char*>(recv_buff), bytes);

            PortInfo port_info;
            port_info.open = true;
            port_info.proto = SOCK_STREAM;
            port_info.read = received_str;
            port_info.port_number = port;

            result.push_back(port_info);

            close(sock);
        }
        catch (const std::exception& e) {
            close(sock);
            std::cerr << "ScanAddressPlainTCP: " << e.what() << std::endl;
        }
    }

    return result;
}

std::vector<PortInfo> ScanAddressSSLTCP(std::string& ip, std::map<unsigned short, std::string>& ports_data) {
    std::vector<PortInfo> result;

    for (const auto port_data : ports_data) {
        int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

        try {
            unsigned short port = port_data.first;
            std::string payload = port_data.second;

            sockaddr_in addr;
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

            unsigned char send_buff[SEND_BUFF_SIZE]; memset(send_buff, 0, SEND_BUFF_SIZE);
            unsigned char recv_buff[RECV_BUFF_SIZE]; memset(recv_buff, 0, RECV_BUFF_SIZE);

            int connection_result = connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
            if (connection_result < 0) {
                PortInfo port_info;
                port_info.open = false;
                port_info.port_number = port;

                result.push_back(port_info);

                close(sock);
                continue;
            }

            // Manual memcpy
            for (unsigned int i = 0; i < SEND_BUFF_SIZE && i < payload.length(); i++) {
                send_buff[i] = payload[i];
            }

            const SSL_METHOD* ssl_method = TLS_client_method();

            SSL_CTX* ctx = SSL_CTX_new(ssl_method);
            SSL* ssl = SSL_new(ctx);

            SSL_set_fd(ssl, sock);
            int ssl_error = SSL_connect(ssl);
            if (ssl_error <= 0) {
                close(sock);

                SSL_shutdown(ssl);
                SSL_free(ssl);
                SSL_CTX_free(ctx);

                continue;
            }

            SSL_write(ssl, send_buff, SEND_BUFF_SIZE);
            unsigned int bytes = SSL_read(ssl, recv_buff, RECV_BUFF_SIZE);

            SSL_shutdown(ssl);
            SSL_free(ssl);
            SSL_CTX_free(ctx);

            std::string received_str(reinterpret_cast<const char*>(recv_buff), bytes);

            PortInfo port_info;
            port_info.open = true;
            port_info.proto = SOCK_STREAM;
            port_info.read = received_str;
            port_info.port_number = port;

            result.push_back(port_info);

            close(sock);
        }
        catch (const std::exception& e) {
            close(sock);
            std::cerr << "ScanAddressSSLTCP: " << e.what() << std::endl;
        }
    }

    return result;
}

std::vector<PortInfo> ScanAddressPlainUDP(std::string& ip, std::map<unsigned short, std::string>& ports_data) {
    std::vector<PortInfo> result;

    for (const auto port_data : ports_data) {
        int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        
        try {
            socket_timeout(sock, SOCK_TIMEOUT_SECONDS);

            unsigned short port = port_data.first;
            std::string payload = port_data.second;

            sockaddr_in addr;
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
            socklen_t addr_length = sizeof(addr);

            unsigned char send_buff[SEND_BUFF_SIZE]; memset(send_buff, 0, SEND_BUFF_SIZE);
            unsigned char recv_buff[RECV_BUFF_SIZE]; memset(recv_buff, 0, RECV_BUFF_SIZE);

            sendto(sock, send_buff, SEND_BUFF_SIZE, 0, reinterpret_cast<sockaddr*>(&addr), addr_length);
            int bytes = recvfrom(sock, recv_buff, RECV_BUFF_SIZE, 0, reinterpret_cast<sockaddr*>(&addr), &addr_length);
            if (bytes <= 0) {
                PortInfo port_info;
                port_info.open = false;
                port_info.port_number = port;

                result.push_back(port_info);

                close(sock);
                continue;
            }

            std::string received_str(reinterpret_cast<const char*>(recv_buff), bytes);

            PortInfo port_info;
            port_info.open = true;
            port_info.proto = SOCK_DGRAM;
            port_info.read = received_str;
            port_info.port_number = port;

            result.push_back(port_info);

            close(sock);
        }
        catch (const std::exception& e) {
            close(sock);
            std::cerr << "ScanAddressPlainUDP: " << e.what() << std::endl;
        }
    }

    return result;
}