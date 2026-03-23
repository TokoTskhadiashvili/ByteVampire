#pragma once

#include <toml++/toml.hpp>

#include <string.h>

#include <string>
#include <vector>
#include <regex>

struct MatchRule {
    std::string service;
    std::string version;
    std::regex regex;
};

struct TemplateInformation {
    std::string name;
    char proto[3];
    std::string payload;

    std::vector<unsigned short> plain_ports;
    std::vector<unsigned short> ssl_ports;

    std::vector<MatchRule> rules;
};