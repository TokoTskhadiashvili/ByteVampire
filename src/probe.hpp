#pragma once

#include <toml++/toml.hpp>

#include <optional>
#include <regex>
#include <string>
#include <map>

#include <iostream>

struct MatchRule {
    std::string service;
    std::regex regex;
    std::string product;
    std::string version;
};

struct ProbeInfo {
    std::string name;
    std::string protocol;
    std::string payload;

    std::vector<unsigned short> plain_ports;
    std::vector<unsigned short> ssl_ports;
    std::vector<MatchRule> matches;
};

std::optional<ProbeInfo> ParseProbeFile(const std::string& name) {
    try {
        toml::table toml_table = toml::parse_file(name);

        ProbeInfo probe_info;

        probe_info.name = toml_table["name"].value_or("");
        probe_info.protocol = toml_table["protocol"].value_or("");
        probe_info.payload = toml_table["payload"].value_or("");

        if (auto ports = toml_table["plain_ports"].as_array()) {
            for (auto&& port : *ports) {
                if (auto p = port.value<unsigned short>()) {
                    if (*p > 0 && *p <= 65535) {
                        probe_info.plain_ports.push_back(*p);
                    }
                }
            }
        }

        if (auto ports = toml_table["ssl_ports"].as_array()) {
            for (auto&& port : *ports) {
                if (auto p = port.value<unsigned short>()) {
                    if (*p > 0 && *p <= 65535) {
                        probe_info.ssl_ports.push_back(*p);
                    }
                }
            }
        }

        if (auto matches = toml_table["match"].as_array()) {
            for (auto&& node : *matches) {
                auto node_table = node.as_table();
                if (!node_table) { continue; }

                MatchRule rule;

                if (node_table->contains("regex")) {
                    rule.regex = std::regex((*node_table)["regex"].value_or(""), std::regex::ECMAScript | std::regex::optimize);
                }
                else {
                    rule.regex = std::regex("", std::regex::ECMAScript | std::regex::optimize);
                }

                if (node_table->contains("service")) {
                    rule.service = (*node_table)["service"].value_or("");
                }
                else {
                    rule.service = "";
                }

                if (node_table->contains("product")) {
                    rule.product = (*node_table)["service"].value_or("");
                }
                else {
                    rule.product = "";
                }

                if (node_table->contains("version")) {
                    rule.version = (*node_table)["version"].value_or("");
                }
                else {
                    rule.version = "";
                }

                probe_info.matches.emplace_back(std::move(rule));
            }
        }

        return probe_info;
    }
    catch (const std::exception& e) {
        std::cerr << "Probe parse error: " << e.what() << std::endl;
        return std::nullopt;
    }
}