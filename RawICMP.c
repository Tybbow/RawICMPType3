#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <unistd.h>

struct icmp_pmtud {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t unused;
    uint16_t mtu;
};

unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2) sum += *buf++;
    if (len == 1) sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

int main(int argc, char *argv[]) {
    int sockfd;
    char packet[1024];
    memset(packet, 0, sizeof(packet));

    char *src_ip_str = "172.20.10.3";
    char *dst_ip_str = "8.8.8.8";

    struct iphdr *ip = (struct iphdr *) packet;
    struct icmp_pmtud *icmp = (struct icmp_pmtud *) (packet + sizeof(struct iphdr));
    
    unsigned char shellcode[] = {
        0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    memcpy(icmp, shellcode, sizeof(shellcode));
    
    int icmp_len = sizeof(shellcode);
    
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + icmp_len);
    ip->id = htons(rand() % 65535);
    ip->frag_off = htons(0x4000);
    ip->ttl = 128;
    ip->protocol = IPPROTO_ICMP;
    ip->check = 0;
    ip->saddr = inet_addr(src_ip_str);
    ip->daddr = inet_addr(dst_ip_str);
    ip->check = checksum((unsigned short *) ip, sizeof(struct iphdr));

    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    int one = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = ip->daddr;

    int packet_size = sizeof(struct iphdr) + icmp_len;
    if (sendto(sockfd, packet, packet_size, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("sendto");
        exit(EXIT_FAILURE);
    } else {
        printf("Paquet ICMP 'Packet Too Big' envoyé avec succès.\n");
    }

    close(sockfd);
    return 0;
}
