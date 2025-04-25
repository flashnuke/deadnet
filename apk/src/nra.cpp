#include <iostream>
#include <cstring>
#include <cstdlib>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>    // usleep
#include <chrono>

#define ND_RA_FLAG_RTPREF_HIGH 0x08

struct nd_opt_slla {
    struct nd_opt_hdr hdr;
    uint8_t hw_addr[6];
};

int main(int argc, char* argv[]) {
    // 7 args: hwaddr, src_ip, prefix, prefix_len, iface, sleep_sec
    if (argc != 7) {
        return 1;
    }

    const char* slla_mac_str = argv[1];
    const char* src_ip_str   = argv[2];
    const char* prefix_str   = argv[3];
    int         prefix_len   = std::atoi(argv[4]);
    const char* iface        = argv[5];
    double      sleep_sec    = std::atof(argv[6]);
    useconds_t  sleep_us     = (useconds_t)(sleep_sec * 1e6);

    // build raw IPv6 socket
    int sock = socket(PF_INET6, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        return 1;
    }
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE,
                   iface, std::strlen(iface)) < 0) {
        close(sock);
        return 1;
    }

    // source and destination addresses
    struct sockaddr_in6 src_addr = {}, dest_addr = {};
    src_addr.sin6_family = AF_INET6;
    dest_addr.sin6_family = AF_INET6;
    inet_pton(AF_INET6, src_ip_str,   &src_addr.sin6_addr);
    inet_pton(AF_INET6, "ff02::1",    &dest_addr.sin6_addr);

    // prepare IPv6 header
    struct ip6_hdr ip_header = {};
    ip_header.ip6_ctlun.ip6_un1.ip6_un1_flow = htonl((6 << 28));
    ip_header.ip6_ctlun.ip6_un1.ip6_un1_plen = htons(
        sizeof(struct nd_router_advert)
      + sizeof(struct nd_opt_prefix_info)
      + sizeof(struct nd_opt_slla)
    );
    ip_header.ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_ICMPV6;
    ip_header.ip6_ctlun.ip6_un1.ip6_un1_hlim = 255;
    ip_header.ip6_src = src_addr.sin6_addr;
    ip_header.ip6_dst = dest_addr.sin6_addr;

    // build ICMPv6 RA header
    struct nd_router_advert ra = {};
    ra.nd_ra_hdr.icmp6_type = ND_ROUTER_ADVERT;
    ra.nd_ra_hdr.icmp6_code = 0;
    ra.nd_ra_curhoplimit    = 255;
    ra.nd_ra_flags_reserved = ND_RA_FLAG_RTPREF_HIGH;
    ra.nd_ra_router_lifetime = 0;  // dead router

    // parse source link-layer address option
    struct nd_opt_slla slla = {};
    slla.hdr.nd_opt_type = ND_OPT_SOURCE_LINKADDR;
    slla.hdr.nd_opt_len  = 1;
    sscanf(slla_mac_str,
           "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &slla.hw_addr[0], &slla.hw_addr[1],
           &slla.hw_addr[2], &slla.hw_addr[3],
           &slla.hw_addr[4], &slla.hw_addr[5]);

    // build prefix info option
    struct nd_opt_prefix_info pi = {};
    pi.nd_opt_pi_type         = ND_OPT_PREFIX_INFORMATION;
    pi.nd_opt_pi_len          = sizeof(pi) / 8;
    pi.nd_opt_pi_prefix_len   = prefix_len;
    pi.nd_opt_pi_flags_reserved =
        ND_OPT_PI_FLAG_ONLINK | ND_OPT_PI_FLAG_AUTO;
    pi.nd_opt_pi_valid_time      = htonl(86400);
    pi.nd_opt_pi_preferred_time  = htonl(14400);
    inet_pton(AF_INET6, prefix_str, &pi.nd_opt_pi_prefix);

    // pseudo-header for checksum
    struct {
        struct in6_addr src, dst;
        uint32_t        plen;
        uint8_t        zeros[3];
        uint8_t        nxt;
    } pseudo = {};
    pseudo.src   = src_addr.sin6_addr;
    pseudo.dst   = dest_addr.sin6_addr;
    pseudo.plen  = htonl(sizeof(ra) + sizeof(pi) + sizeof(slla));
    pseudo.nxt   = IPPROTO_ICMPV6;

    // assemble ICMPv6 payload & compute checksum
    size_t icmp_len = sizeof(ra) + sizeof(pi) + sizeof(slla);
    uint8_t *icmp_buf = (uint8_t*)malloc(icmp_len);
    memcpy(icmp_buf,      &ra,  sizeof(ra));
    memcpy(icmp_buf+sizeof(ra), &pi,  sizeof(pi));
    memcpy(icmp_buf+sizeof(ra)+sizeof(pi), &slla, sizeof(slla));

    uint32_t sum = 0;
    auto add16 = [&](const uint16_t* ptr, size_t count) {
        for (size_t i = 0; i < count; i++) {
            sum += ntohs(ptr[i]);
        }
    };
    add16((uint16_t*)&pseudo, sizeof(pseudo)/2);
    add16((uint16_t*)icmp_buf, (icmp_len+1)/2);
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    ((struct nd_router_advert*)icmp_buf)->nd_ra_hdr.icmp6_cksum =
        htons(~sum);

    // build full packet
    size_t packet_len = sizeof(ip_header) + icmp_len;
    uint8_t *packet = (uint8_t*)malloc(packet_len);
    memcpy(packet,           &ip_header, sizeof(ip_header));
    memcpy(packet+sizeof(ip_header), icmp_buf, icmp_len);

    free(icmp_buf);

    // endless loop
    while (1) {
        if (sendto(sock, packet, packet_len, 0,
                   (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
        }
        usleep(sleep_us);
    }

    // unreachable, but clean up
    free(packet);
    close(sock);
    return 0;
}
