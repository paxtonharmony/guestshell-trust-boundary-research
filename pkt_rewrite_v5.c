#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#define IFACE    "eth0"
#define SRC_NET  "192.168.57.0"
#define SRC_MASK "255.255.255.0"
#define DST_NET  "192.168.186.0"
#define DST_MASK "255.255.255.0"

static uint8_t GW_MAC[6] = {0x00, 0x1E, 0xBD, 0x02, 0xE0, 0xBD};

static uint16_t checksum(void *b, int len) {
    uint16_t *buf = b;
    uint32_t sum = 0;
    for (; len > 1; len -= 2) sum += *buf++;
    if (len == 1) sum += *(uint8_t *)buf;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

static uint16_t tcp_udp_checksum(struct iphdr *ip, void *transport, int tlen) {
    struct {
        uint32_t src, dst;
        uint8_t  zero, proto;
        uint16_t len;
    } pseudo = {
        ip->saddr, ip->daddr, 0, ip->protocol, htons(tlen)
    };
    uint32_t sum = 0;
    uint16_t *p = (uint16_t *)&pseudo;
    for (int i = 0; i < (int)sizeof(pseudo) / 2; i++) sum += p[i];
    p = transport;
    for (int i = tlen; i > 1; i -= 2) sum += *p++;
    if (tlen & 1) sum += *(uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

static void print_mac(const char *label, uint8_t *mac) {
    printf("%s %02x:%02x:%02x:%02x:%02x:%02x\n",
           label, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <new_src_ip> <new_dst_ip> <orig_dst_ip>\n", argv[0]);
        fprintf(stderr, "  new_src_ip:  rewritten source IP (e.g. 192.168.57.20)\n");
        fprintf(stderr, "  new_dst_ip:  real destination IP (e.g. 192.168.10.20)\n");
        fprintf(stderr, "  orig_dst_ip: virtual destination IP to restore in replies (e.g. 192.168.186.20)\n");
        return 1;
    }

    uint32_t new_src  = inet_addr(argv[1]);
    uint32_t new_dst  = inet_addr(argv[2]);
    uint32_t orig_dst = inet_addr(argv[3]);  /* 回包时还原的虚拟目的 IP */
    uint32_t src_net  = inet_addr(SRC_NET)  & inet_addr(SRC_MASK);
    uint32_t dst_net  = inet_addr(DST_NET)  & inet_addr(DST_MASK);
    uint32_t src_mask = inet_addr(SRC_MASK);
    uint32_t dst_mask = inet_addr(DST_MASK);

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) { perror("socket"); return 1; }

    struct ifreq ifr;
    strncpy(ifr.ifr_name, IFACE, IFNAMSIZ);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) { perror("SIOCGIFINDEX"); return 1; }
    int ifindex = ifr.ifr_ifindex;

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) { perror("SIOCGIFHWADDR"); return 1; }
    uint8_t my_mac[6];
    memcpy(my_mac, ifr.ifr_hwaddr.sa_data, 6);

    struct sockaddr_ll sll = {
        .sll_family   = AF_PACKET,
        .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex  = ifindex,
    };
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) { perror("bind"); return 1; }

    printf("Listening on %s, rewriting src->%s dst->%s (orig_dst=%s)\n",
           IFACE, argv[1], argv[2], argv[3]);
    print_mac("[init] my_mac :", my_mac);
    print_mac("[init] gw_mac :", GW_MAC);
    printf("[init] src_net=%s/%s dst_net=%s/%s\n", SRC_NET, SRC_MASK, DST_NET, DST_MASK);
    printf("[init] fwd: %s/24 -> %s/24  =>  %s -> %s\n", SRC_NET, DST_NET, argv[1], argv[2]);
    printf("[init] rev: %s -> %s/24  =>  src restored to %s\n", argv[2], SRC_NET, argv[3]);
    fflush(stdout);

    uint8_t buf[2048];
    long pkt_count = 0, fwd_count = 0, rev_count = 0;

    for (;;) {
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, NULL, NULL);
        if (n < (ssize_t)(sizeof(struct ethhdr) + sizeof(struct iphdr))) continue;
        pkt_count++;

        struct ethhdr *eth = (struct ethhdr *)buf;
        if (ntohs(eth->h_proto) != ETH_P_IP) continue;

        struct iphdr *ip = (struct iphdr *)(buf + sizeof(struct ethhdr));

        char sip_str[INET_ADDRSTRLEN], dip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip->saddr, sip_str, sizeof(sip_str));
        inet_ntop(AF_INET, &ip->daddr, dip_str, sizeof(dip_str));

        /* 防环路：忽略自己发出的包 */
        if (memcmp(eth->h_source, my_mac, 6) == 0) continue;

        /* ===== 正向改写：SRC_NET -> DST_NET  =>  new_src -> new_dst ===== */
        if ((ip->saddr & src_mask) == src_net && (ip->daddr & dst_mask) == dst_net) {

            printf("[match-fwd] #%ld pkt: %s -> %s  proto=%d ttl=%d len=%d\n",
                   pkt_count, sip_str, dip_str, ip->protocol, ip->ttl, ntohs(ip->tot_len));

            uint8_t old_ttl = ip->ttl;
            ip->ttl  = 64;
            ip->saddr = new_src;
            ip->daddr = new_dst;
            ip->check = 0;
            ip->check = checksum(ip, ip->ihl * 4);

            memcpy(eth->h_dest,   GW_MAC, 6);
            memcpy(eth->h_source, my_mac, 6);

            void *transport_hdr = (uint8_t *)ip + ip->ihl * 4;
            int payload_len = ntohs(ip->tot_len) - ip->ihl * 4;

            if (ip->protocol == IPPROTO_TCP) {
                struct tcphdr *tcp = transport_hdr;
                tcp->check = 0;
                tcp->check = tcp_udp_checksum(ip, tcp, payload_len);
                printf("[rewrite-fwd] TCP  old_ttl=%d -> ttl=64  %s:%d -> %s:%d\n",
                       old_ttl, argv[1], ntohs(tcp->source), argv[2], ntohs(tcp->dest));
            } else if (ip->protocol == IPPROTO_UDP) {
                struct udphdr *udp = transport_hdr;
                udp->check = 0;
                udp->check = tcp_udp_checksum(ip, udp, payload_len);
                printf("[rewrite-fwd] UDP  old_ttl=%d -> ttl=64  %s:%d -> %s:%d\n",
                       old_ttl, argv[1], ntohs(udp->source), argv[2], ntohs(udp->dest));
            } else {
                printf("[rewrite-fwd] proto=%d  old_ttl=%d -> ttl=64\n", ip->protocol, old_ttl);
            }

            struct sockaddr_ll dst_sll = {
                .sll_family  = AF_PACKET,
                .sll_ifindex = ifindex,
                .sll_halen   = ETH_ALEN,
            };
            memcpy(dst_sll.sll_addr, GW_MAC, 6);

            ssize_t sent = sendto(fd, buf, n, 0, (struct sockaddr *)&dst_sll, sizeof(dst_sll));
            if (sent < 0) perror("[error] sendto (fwd)");
            else { fwd_count++; printf("[fwd] #%ld sent %zd bytes  (total fwd=%ld)\n", pkt_count, sent, fwd_count); }
            fflush(stdout);
            continue;
        }

        /* ===== 反向改写：new_dst -> new_src  =>  src 还原为 orig_dst ===== */
        if (ip->saddr == new_dst && ip->daddr == new_src) {

            printf("[match-rev] #%ld pkt: %s -> %s  proto=%d ttl=%d len=%d (REPLY)\n",
                   pkt_count, sip_str, dip_str, ip->protocol, ip->ttl, ntohs(ip->tot_len));

            uint8_t old_ttl = ip->ttl;
            ip->ttl   = 64;
            ip->saddr = orig_dst;   /* 还原：192.168.10.20 -> 192.168.186.20 */
            /* ip->daddr 不变，仍是 192.168.57.20 */
            ip->check = 0;
            ip->check = checksum(ip, ip->ihl * 4);

            memcpy(eth->h_dest,   GW_MAC, 6);
            memcpy(eth->h_source, my_mac, 6);

            void *transport_hdr = (uint8_t *)ip + ip->ihl * 4;
            int payload_len = ntohs(ip->tot_len) - ip->ihl * 4;

            if (ip->protocol == IPPROTO_TCP) {
                struct tcphdr *tcp = transport_hdr;
                tcp->check = 0;
                tcp->check = tcp_udp_checksum(ip, tcp, payload_len);
                printf("[rewrite-rev] TCP  reply old_ttl=%d -> ttl=64  %s -> %s:%d\n",
                       old_ttl, argv[3], argv[1], ntohs(tcp->dest));
            } else if (ip->protocol == IPPROTO_UDP) {
                struct udphdr *udp = transport_hdr;
                udp->check = 0;
                udp->check = tcp_udp_checksum(ip, udp, payload_len);
                printf("[rewrite-rev] UDP  reply old_ttl=%d -> ttl=64  %s -> %s:%d\n",
                       old_ttl, argv[3], argv[1], ntohs(udp->dest));
            } else {
                printf("[rewrite-rev] proto=%d  reply old_ttl=%d -> ttl=64\n", ip->protocol, old_ttl);
            }

            struct sockaddr_ll dst_sll = {
                .sll_family  = AF_PACKET,
                .sll_ifindex = ifindex,
                .sll_halen   = ETH_ALEN,
            };
            memcpy(dst_sll.sll_addr, GW_MAC, 6);

            ssize_t sent = sendto(fd, buf, n, 0, (struct sockaddr *)&dst_sll, sizeof(dst_sll));
            if (sent < 0) perror("[error] sendto (rev)");
            else { rev_count++; printf("[rev] #%ld sent %zd bytes  (total rev=%ld)\n", pkt_count, sent, rev_count); }
            fflush(stdout);
            continue;
        }
    }
    return 0;
}

