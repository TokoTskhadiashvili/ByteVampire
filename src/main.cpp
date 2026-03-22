#include "utils.hpp"
#include "probe.hpp"
#include "scanner.hpp"

int main(void) {
    // Tests for dev
    auto probe_info = ParseProbeFile("./probe.toml");

    std::string ip = "192.168.1.1";
    std::map<unsigned short, std::string> plain_ports_data;
    std::map<unsigned short, std::string> ssl_ports_data;

    for (unsigned short port : probe_info->plain_ports) {
        plain_ports_data[port] = probe_info->payload;
    }

    for (unsigned short port : probe_info->ssl_ports) {
        ssl_ports_data[port] = probe_info->payload;
    }

    std::vector<PortInfo> plain_scan_info = ScanAddressPlainTCP(ip, plain_ports_data);
    std::vector<PortInfo> ssl_scan_info = ScanAddressSSLTCP(ip, ssl_ports_data);

    std::vector<std::regex> regexes;

    for (MatchRule rule : probe_info->matches) {
        regexes.emplace_back(std::move(rule.regex));
    }

    for (PortInfo port_info : plain_scan_info) {
        std::string service_version = GetServiceVersion(port_info.read, regexes);
        if (port_info.open) {
            std::cout << port_info.port_number << "/tcp open" << std::endl;
        }
        else {
            std::cout << port_info.port_number << "/tcp closed" << std::endl;
        }
    }

    for (PortInfo port_info : ssl_scan_info) {
        std::string service_version = GetServiceVersion(port_info.read, regexes);
        if (port_info.open) {
            std::cout << port_info.port_number << "/tcp open" << std::endl;
            std::cout << service_version << std::endl;
        }
        else {
            std::cout << port_info.port_number << "/tcp closed" << std::endl;
        }
    }

    return 0;
}