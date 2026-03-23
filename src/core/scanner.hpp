#pragma once

#define SEND_BUFFER_SIZE 1024
#define RECV_BUFFER_SIZE 1024

#define SOCKET_TIMEOUT_SECONDS 5

#include <iostream>
#include <string>
#include <vector>
#include <regex>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

struct PortInformation {
    unsigned short number;
    char proto[3];
    bool is_open;

    char read[RECV_BUFFER_SIZE];

    std::string version;
    std::vector<std::string> cve_list;
};

std::string GetServiceVersion(const std::string& data, const std::vector<std::regex>& regex_list);

std::vector<PortInformation> ScanPlainTCP(std::string& ip, std::map<unsigned short, std::string>& port_data);
std::vector<PortInformation> ScanSSLTCP(std::string& ip, std::map<unsigned short, std::string>& port_data);
std::vector<PortInformation> ScanPlainUDP(std::string& ip, std::map<unsigned short, std::string>& port_data);
std::vector<PortInformation> ScanSSLUDP(std::string& ip, std::map<unsigned short, std::string> port_data);