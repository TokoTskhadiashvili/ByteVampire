#pragma once

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sysexits.h>
#include <ifaddrs.h>
#include <net/if.h>

#include <string>
#include <vector>

#include <iostream>

struct InterfaceInfo {
    std::string name;

    std::string ip_address;
    std::string netmask;
};

std::vector<InterfaceInfo> GetInterfaceAddresses() {
    std::vector<InterfaceInfo> result;
    
    struct ifaddrs* interface_addresses = nullptr;

    try {
        auto fetch_result = getifaddrs(&interface_addresses);
        if (fetch_result != 0) { return result; }

        for (struct ifaddrs* entry = interface_addresses; entry != nullptr; entry = entry->ifa_next) {
            std::string ip_address;
            std::string netmask;

            std::string interface = std::string(entry->ifa_name);
            
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
                // AF_UNIX, AF_PACKET later
            }

            InterfaceInfo interface_info;

            interface_info.name = interface;
            interface_info.ip_address = ip_address;
            interface_info.netmask = netmask;

            result.push_back(interface_info);
        }

        freeifaddrs(interface_addresses);
    }
    catch (const std::exception& e) {
        std::cerr << "GetInterfaceAddresses: " << e.what() << std::endl;
    }

    return result;
}