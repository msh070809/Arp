#pragma once
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <iostream>
#include <cstring>
#include <string>

std::string getIPAddress(const std::string& interfaceName);
