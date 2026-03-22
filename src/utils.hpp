#pragma once

#include <string>

#include <arpa/inet.h>

std::string trim(const std::string& str) {
    const char* chars = " \t\n\r";
    size_t start = str.find_first_not_of(chars);
    size_t end = str.find_last_not_of(chars);

    return (start == std::string::npos) ? "" : str.substr(start, end - start + 1);
}

void socket_timeout(int& sock, int seconds) {
    struct timeval time_val;
    time_val.tv_sec = seconds;
    time_val.tv_usec = 0;

    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &time_val, sizeof(time_val)) < 0) { return; }

    return;
}