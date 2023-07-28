#include "GetMac.h"

std::string getMacAddress(const std::string& interfaceName) {
    std::string command = "ifconfig " + interfaceName;

    // 시스템 명령 실행 및 결과를 받을 임시 파일 설정
    std::string tmpFileName = "/tmp/mac_addr_output.txt";
    command += " > " + tmpFileName;

    // 시스템 명령 실행
    int result = system(command.c_str());

    std::string macAddress;

    if (result == 0) {
        // 명령이 성공적으로 실행되면, 파일에서 MAC 주소를 읽음
        std::string readCommand = "grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}' " + tmpFileName;
        FILE* file = popen(readCommand.c_str(), "r");
        char buffer[18];
        if (file) {
            if (fgets(buffer, sizeof(buffer), file) != nullptr) {
                macAddress = buffer;
            }
            pclose(file);
        }
    }

    // 임시 파일 삭제
    std::string removeCommand = "rm " + tmpFileName;
    system(removeCommand.c_str());

    return macAddress;
}

