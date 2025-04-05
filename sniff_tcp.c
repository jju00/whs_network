#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include "myheader.h"
#include <ctype.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    // IP 패킷인지 확인 (ether_type == 0x0800)
    if (ntohs(eth->ether_type) == 0x0800) {
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        // TCP 패킷인지 확인
        if (ip->iph_protocol == IPPROTO_TCP) {
            int ip_header_len = ip->iph_ihl * 4;

            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);
            int tcp_header_len = TH_OFF(tcp) * 4;

            const u_char *payload = packet + sizeof(struct ethheader) + ip_header_len + tcp_header_len;
            int payload_len = ntohs(ip->iph_len) - ip_header_len - tcp_header_len;

            // 출력
            printf("=== TCP Packet Captured ===\n");
            printf("Ethernet Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
                   eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
            printf("Ethernet Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
                   eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

            printf("From: %s\n", inet_ntoa(ip->iph_sourceip));
            printf("To  : %s\n", inet_ntoa(ip->iph_destip));

            printf("Src Port: %u\n", ntohs(tcp->tcp_sport));
            printf("Dst Port: %u\n", ntohs(tcp->tcp_dport));

            // 메시지도 출력 (최대 16바이트만)
            printf("Payload (최대 16바이트): ");
            for (int i = 0; i < payload_len && i < 16; i++) {
                printf("%c", isprint(payload[i]) ? payload[i] : '.');
            }
            printf("\n\n");
        }
    }
}

int main() {
    char *dev = "ens33"; // ip a로 확인한 인터페이스 이름에 맞게 변경
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;
    
    // 1. 세션 열기
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    // 2. 필터 설정 (TCP만)
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    // 3. 패킷 수신 루프
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}
