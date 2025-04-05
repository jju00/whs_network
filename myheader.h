#ifndef MYHEADER_H
#define MYHEADER_H

#include <netinet/in.h>

/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[6]; // dst mac
    u_char  ether_shost[6]; // src mac
    u_short ether_type;
};

/* IP Header */
struct ipheader {
    unsigned char iph_ihl:4, iph_ver:4;
    unsigned char iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_flag:3, iph_offset:13;
    unsigned char iph_ttl;
    unsigned char iph_protocol;
    unsigned short int iph_chksum;
    struct in_addr iph_sourceip;  // src ip
    struct in_addr iph_destip;  // dst ip
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;  // src tcp
    u_short tcp_dport;  // dst tcp
    u_int   tcp_seq;
    u_int   tcp_ack;
    u_char  tcp_offx2;
    u_char  tcp_flags;
    u_short tcp_win;
    u_short tcp_sum;
    u_short tcp_urp;
};

#define TH_OFF(th) (((th)->tcp_offx2 & 0xf0) >> 4)

#endif
