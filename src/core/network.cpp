#include "network.hpp"

std::vector<std::string> GetInterfaces() {
    std::vector<std::string> result;

    struct ifaddrs* interface_addresses = nullptr;

    try {
        auto fetch_result = getifaddrs(&interface_addresses);
        if (fetch_result != 0) { return result; }

        for (struct ifaddrs* entry = interface_addresses; entry != nullptr; entry = entry->ifa_next) {
            result.push_back(entry->ifa_name);
        }
    }
    catch (const std::exception& e) {
        std::cerr << "GetInterfaces: " << e.what() << std::endl;
    }

    return result;
}

InterfaceInformation GetInterfaceInfo(std::string& name) {
    InterfaceInformation result;

    struct ifaddrs* interface_addresses = nullptr;

    try {
        auto fetch_result = getifaddrs(&interface_addresses);
        if (fetch_result != 0) { return result; }

        for (struct ifaddrs* entry = interface_addresses; entry != nullptr; entry = entry->ifa_next) {
            if (strcmp(entry->ifa_name, name.c_str()) != 0) {
                continue;
            }

            std::string ip_address;
            std::string netmask;

            sa_family_t addr_family = entry->ifa_addr->sa_family;
            if (addr_family == AF_INET) {
                if (entry->ifa_addr != nullptr) {
                    char buff[INET_ADDRSTRLEN] = { 0, };
                    inet_ntop(addr_family, &((struct sockaddr_in*)(entry->ifa_addr))->sin_addr, buff, INET_ADDRSTRLEN);

                    ip_address = std::string(buff);
                }

                if (entry->ifa_netmask != nullptr) {
                    char buff[INET_ADDRSTRLEN] = { 0, };
                    inet_ntop(addr_family, &((struct sockaddr_in*)(entry->ifa_netmask))->sin_addr, buff, INET_ADDRSTRLEN);

                    netmask = std::string(buff);
                }
            }
            else if (addr_family == AF_INET6) {
                uint32_t scope_id = 0;
                if (entry->ifa_addr != nullptr) {
                    char buff[INET6_ADDRSTRLEN] = { 0, };
                    inet_ntop(addr_family, &((struct sockaddr_in6*)(entry->ifa_addr))->sin6_addr, buff, INET6_ADDRSTRLEN);

                    ip_address = std::string(buff);
                }

                if (entry->ifa_netmask != nullptr) {
                    char buff[INET6_ADDRSTRLEN] = { 0, };
                    inet_ntop(addr_family, &((struct sockaddr_in6*)(entry->ifa_netmask))->sin6_addr, buff, INET6_ADDRSTRLEN);

                    netmask = std::string(buff);
                }
            }
            else {
                continue;
            }

            result.name = name;
            result.ip_address = ip_address;
            result.netmask = netmask;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "GetInterfaceInfo: " << e.what() << std::endl;
    }

    return result;
}