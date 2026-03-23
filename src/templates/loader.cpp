#include "loader.hpp"

ProbeInformation ParseProbeFile(const std::string& name) {
    ProbeInformation result;

    try {
        toml::table toml_table = toml::parse_file(name);

        result.name = toml_table["name"].value_or("");
        sprintf(result.proto, "%s", toml_table["proto"].value_or(""));
        result.payload = toml_table["payload"].value_or("");

        if (auto ports = toml_table["plain_ports"].as_array()) {
            for (auto&& port : *ports) {
                if (auto p = port.value<unsigned short>()) {
                    if (*p > 0 && *p <= 65535) {
                        result.plain_ports.push_back(*p);
                    }
                }
            }
        }

        if (auto ports = toml_table["ssl_ports"].as_array()) {
            for (auto&& port : *ports) {
                if (auto p = port.value<unsigned short>()) {
                    if (*p > 0 && *p <= 65535) {
                        result.ssl_ports.push_back(*p);
                    }
                }
            }
        }

        if (auto matches = toml_table["match"].as_array()) {
            for (auto&& node : *matches) {
                auto node_table = node.as_table();
                if (!node_table) { continue; }

                ProbeMatchRule match_rule;

                if (node_table->contains("regex")) {
                    match_rule.regex = std::regex((*node_table)["regex"].value_or(""), std::regex::ECMAScript | std::regex::optimize);
                }
                else {
                    match_rule.regex = std::regex("", std::regex::ECMAScript | std::regex::optimize);
                }

                if (node_table->contains("service")) {
                    match_rule.service = (*node_table)["service"].value_or("");
                }
                else {
                    match_rule.service = "";
                }

                if (node_table->contains("version")) {
                    match_rule.version = (*node_table)["version"].value_or("");
                }
                else {
                    match_rule.version = "";
                }

                result.rules.emplace_back(std::move(match_rule));
            }
        }
    }
    catch (const std::exception& e) {
        std::cerr << "ParseProbeFile: " << e.what() << std::endl;
    }
    
    return result;
}
