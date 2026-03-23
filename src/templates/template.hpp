#pragma once

#include <toml++/toml.hpp>

#include <string.h>

#include <string>
#include <vector>
#include <regex>

struct ProbeMatchRule {
    std::string service;
    std::string version;
    std::regex regex;
};

struct ProbeInformation {
    std::string name;
    char proto[3];
    std::string payload;

    std::vector<unsigned short> plain_ports;
    std::vector<unsigned short> ssl_ports;

    std::vector<ProbeMatchRule> rules;
};

struct ExploitInformation {
    std::string name;

    std::string service;
    std::regex version;

    std::string payload;
    std::regex success_regex;

    bool is_ssl;
};
