#include "scanner.hpp"

std::string trim(const std::string& str) {
    const char* chars = " \t\n\r";
    size_t start = str.find_first_not_of(chars);
    size_t end = str.find_last_not_of(chars);

    return (start == std::string::npos) ? "" : str.substr(start, end - start + 1);
}

void set_tcp_socket_timeout(int& sock, int seconds) {
    struct timeval time_val;
    time_val.tv_sec = seconds;
    time_val.tv_usec = 0;

    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &time_val, sizeof(time_val)) < 0) { return; }

    return;
}

void set_udp_socket_timeout(int& sock, BIO*& bio, int seconds) {
    struct timeval time_val;
    time_val.tv_sec = seconds;
    time_val.tv_usec = 0;

    BIO_ctrl(bio, 103 /* BIO_CTRL_DGRAM_SET_TIMEOUT */, 0, &time_val);

    return;
}

std::string GetServiceVersion(const std::string& read, const std::vector<std::regex>& regex_list) {
    for (const std::regex& regex : regex_list) {
        std::smatch match;

        if (std::regex_search(read, match, regex)) {
            return match[0].str();
        }
    }

    return "";
}

std::vector<PortInformation> ScanPlainTCP(std::string& ip, std::map<unsigned short, std::string>& port_data) {
    std::vector<PortInformation> result;

    for (const auto port_datum : port_data) {
        int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

        unsigned char* send_buff = static_cast<unsigned char*>(malloc(SEND_BUFFER_SIZE));
        unsigned char* recv_buff = static_cast<unsigned char*>(malloc(RECV_BUFFER_SIZE));

        memset(send_buff, 0, SEND_BUFFER_SIZE);
        memset(recv_buff, 0, RECV_BUFFER_SIZE);

        try {
            unsigned short port = port_datum.first;
            std::string payload = port_datum.second;

            sockaddr_in addr;
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

            int connect_result = connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
            if (connect_result < 0) {
                PortInformation port_info;

                port_info.is_open = false;
                port_info.number = port;
                sprintf(port_info.proto, "tcp");

                result.push_back(port_info);

                close(sock);
                free(send_buff);
                free(recv_buff);
                continue;
            }

            for (unsigned int i = 0; i < SEND_BUFFER_SIZE && i < payload.length(); i++) {
                send_buff[i] = payload[i];
            }

            send(sock, send_buff, SEND_BUFFER_SIZE, 0);
            int bytes = recv(sock, recv_buff, RECV_BUFFER_SIZE, 0);
            if (bytes <= 0) {
                PortInformation port_info;

                port_info.is_open = false;
                port_info.number = port;
                sprintf(port_info.proto, "tcp");

                result.push_back(port_info);

                close(sock);
                free(send_buff);
                free(recv_buff);
                continue;
            }

            std::string received_string(reinterpret_cast<const char*>(recv_buff), bytes);

            PortInformation port_info;
            port_info.number = port;
            sprintf(port_info.proto, "tcp");
            sprintf(port_info.read, "%s", received_string.c_str());
            // Try to get version here
            // Try to get cves here

            result.push_back(port_info);

            free(send_buff);
            free(recv_buff);
            close(sock);
        }
        catch (const std::exception& e) {
            close(sock);
            std::cerr << "ScanPlainTCP: " << e.what() << std::endl;
        }

        free(send_buff);
        free(recv_buff);
    }

    return result;
}

std::vector<PortInformation> ScanSSLTCP(std::string& ip, std::map<unsigned short, std::string>& port_data) {
    std::vector<PortInformation> result;

    for (const auto port_datum : port_data) {
        int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

        unsigned char* send_buff = static_cast<unsigned char*>(malloc(SEND_BUFFER_SIZE));
        unsigned char* recv_buff = static_cast<unsigned char*>(malloc(RECV_BUFFER_SIZE));

        memset(send_buff, 0, SEND_BUFFER_SIZE);
        memset(recv_buff, 0, RECV_BUFFER_SIZE);

        try {
            unsigned short port = port_datum.first;
            std::string payload = port_datum.second;

            sockaddr_in addr;
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

            int connect_result = connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
            if (connect_result < 0) {
                PortInformation port_info;

                port_info.is_open = false;
                port_info.number = port;
                sprintf(port_info.proto, "tcp");

                result.push_back(port_info);

                close(sock);
                free(send_buff);
                free(recv_buff);
                continue;
            }

            for (unsigned int i = 0; i < SEND_BUFFER_SIZE && i < payload.length(); i++) {
                send_buff[i] = payload[i];
            }

            const SSL_METHOD* ssl_method = TLS_client_method();

            SSL_CTX* ssl_ctx = SSL_CTX_new(ssl_method);
            SSL* ssl = SSL_new(ssl_ctx);

            SSL_set_fd(ssl, sock);
            int ssl_error = SSL_connect(ssl);
            if (ssl_error <= 0) {
                PortInformation port_info;

                port_info.is_open = false;
                port_info.number = port;
                sprintf(port_info.proto, "tcp");

                result.push_back(port_info);

                close(sock);

                SSL_shutdown(ssl);
                SSL_free(ssl);
                SSL_CTX_free(ssl_ctx);

                free(send_buff);
                free(recv_buff);

                continue;
            }

            SSL_write(ssl, send_buff, SEND_BUFFER_SIZE);
            int bytes = SSL_read(ssl, recv_buff, RECV_BUFFER_SIZE);
            if (bytes <= 0) {
                PortInformation port_info;

                port_info.is_open = false;
                port_info.number = port;
                sprintf(port_info.proto, "tcp");

                result.push_back(port_info);

                SSL_shutdown(ssl);
                SSL_free(ssl);
                SSL_CTX_free(ssl_ctx);

                close(sock);
                free(send_buff);
                free(recv_buff);
                continue;
            }

            SSL_shutdown(ssl);
            SSL_free(ssl);
            SSL_CTX_free(ssl_ctx);

            std::string received_string(reinterpret_cast<const char*>(recv_buff), bytes);

            PortInformation port_info;
            port_info.is_open = true;
            sprintf(port_info.proto, "tcp");
            sprintf(port_info.read, "%s", recv_buff);
            port_info.number = port;

            result.push_back(port_info);

            close(sock);
        }
        catch (const std::exception& e) {
            close(sock);
            std::cerr << "ScanSSLTCP: " << e.what() << std::endl;
        }

        free(send_buff);
        free(recv_buff);
    }

    return result;
}

std::vector<PortInformation> ScanPlainUDP(std::string& ip, std::map<unsigned short, std::string>& port_data) {
    std::vector<PortInformation> result;

    for (const auto port_datum : port_data) {
        int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

        unsigned char* send_buff = static_cast<unsigned char*>(malloc(SEND_BUFFER_SIZE));
        unsigned char* recv_buff = static_cast<unsigned char*>(malloc(RECV_BUFFER_SIZE));

        memset(send_buff, 0, SEND_BUFFER_SIZE);
        memset(recv_buff, 0, RECV_BUFFER_SIZE);

        try {
            set_tcp_socket_timeout(sock, SOCKET_TIMEOUT_SECONDS);

            unsigned short port = port_datum.first;
            std::string payload = port_datum.second;

            sockaddr_in addr;
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
            socklen_t addr_length = sizeof(addr);

            for (unsigned int i = 0; i < SEND_BUFFER_SIZE && i < payload.length(); i++) {
                send_buff[i] = payload[i];
            }

            sendto(sock, send_buff, SEND_BUFFER_SIZE, 0, reinterpret_cast<sockaddr*>(&addr), addr_length);
            int bytes = recvfrom(sock, recv_buff, RECV_BUFFER_SIZE, 0, reinterpret_cast<sockaddr*>(&addr), &addr_length);
            if (bytes <= 0) {
                PortInformation port_info;
                port_info.is_open = false;
                sprintf(port_info.proto, "udp");
                port_info.number = port;

                result.push_back(port_info);

                close(sock);
                free(send_buff);
                free(recv_buff);
                continue;
            }

            std::string received_string(reinterpret_cast<const char*>(recv_buff), bytes);

            PortInformation port_info;
            port_info.is_open = true;
            sprintf(port_info.proto, "udp");
            sprintf(port_info.read, "%s", recv_buff);
            port_info.number = port;

            result.push_back(port_info);

            close(sock);
        }
        catch (const std::exception& e) {
            close(sock);
            std::cerr << "ScanPlainUDP: " << e.what() << std::endl;
        }

        free(send_buff);
        free(recv_buff);
    }

    return result;
}

std::vector<PortInformation> ScanSSLUDP(std::string& ip, std::map<unsigned short, std::string> port_data) {
    std::vector<PortInformation> result;

    for (const auto port_datum : port_data) {
        int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

        unsigned char* send_buff = static_cast<unsigned char*>(malloc(SEND_BUFFER_SIZE));
        unsigned char* recv_buff = static_cast<unsigned char*>(malloc(RECV_BUFFER_SIZE));

        memset(send_buff, 0, SEND_BUFFER_SIZE);
        memset(recv_buff, 0, RECV_BUFFER_SIZE);

        try {
            unsigned short port = port_datum.first;
            std::string payload = port_datum.second;
            
            sockaddr_in addr;
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
            socklen_t addr_length = sizeof(addr);
            
            const SSL_METHOD* ssl_method = DTLS_client_method();
            
            SSL_CTX* ssl_ctx = SSL_CTX_new(ssl_method);
            SSL* ssl = SSL_new(ssl_ctx);
            
            BIO* bio = BIO_new_dgram(sock, BIO_NOCLOSE);
            SSL_set_bio(ssl, bio, bio);
            
            set_udp_socket_timeout(sock, bio, SOCKET_TIMEOUT_SECONDS);

            SSL_write(ssl, send_buff, SEND_BUFFER_SIZE);
            int bytes = SSL_read(ssl, recv_buff, RECV_BUFFER_SIZE);
            if (bytes <= 0) {
                PortInformation port_info;
                port_info.is_open = false;
                sprintf(port_info.proto, "udp");
                port_info.number = port;

                result.push_back(port_info);

                close(sock);
                free(send_buff);
                free(recv_buff);
                continue;
            }

            std::string received_string(reinterpret_cast<const char*>(recv_buff), bytes);

            PortInformation port_info;
            port_info.is_open = true;
            sprintf(port_info.proto, "udp");
            sprintf(port_info.read, "%s", recv_buff);
            port_info.number = port;

            result.push_back(port_info);

            close(sock);
        }
        catch (const std::exception& e) {
            close(sock);
            std::cerr << "ScanSSLUDP: " << e.what() << std::endl;
        }

        free(send_buff);
        free(recv_buff);
    }

    return result;
}