#pragma once

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sysexits.h>
#include <ifaddrs.h>
#include <net/if.h>

#include <string.h>

#include <string>
#include <vector>

#include <iostream>

struct InterfaceInformation {
    std::string name;

    std::string ip_address;
    std::string netmask;
};

std::vector<std::string> GetInterfaces();
InterfaceInformation GetInterfaceInfo(std::string& name);