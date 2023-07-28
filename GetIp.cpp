#include "GetIp.h"

std::string getIPAddress(const std::string& interfaceName) {
    struct ifaddrs *ifap, *ifa;
    std::string ipAddress;

    if (getifaddrs(&ifap) == -1) {
        std::cerr << "Error: Failed to get interface addresses." << std::endl;
        return ipAddress;
    }

    for (ifa = ifap; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr || ifa->ifa_addr->sa_family != AF_INET)
            continue;

        if (strcmp(ifa->ifa_name, interfaceName.c_str()) == 0) {
            char ipBuf[INET_ADDRSTRLEN];
            struct sockaddr_in* sa = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr);
            inet_ntop(AF_INET, &(sa->sin_addr), ipBuf, INET_ADDRSTRLEN);
            ipAddress = ipBuf;
            break;
        }
    }

    freeifaddrs(ifap);

    return ipAddress;
}

