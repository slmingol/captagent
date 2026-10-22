/*
 * captagent - Homer capture agent. Modular
 * ERSPAN/GRE transport module
 *
 * Encapsulates captured SIP/RTP in GRE or ERSPAN (Type I/II/III) and sends
 * via raw socket to a remote collector (e.g. Ativa probe). Ativa handles
 * fragmented GRE/ERSPAN at the network layer, unlike HEP/UDP where
 * fragmented datagrams are dropped.
 *
 * Author: slmingol
 * License: GPLv3
 */

#ifndef _TRANSPORT_ERSPAN_H_
#define _TRANSPORT_ERSPAN_H_

#include <captagent/xmlread.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pthread.h>

#ifdef USE_IPv6
#include <netinet/ip6.h>
#endif

/* ERSPAN/GRE protocol constants */
#define GRE_PROTO               47
#define GRE_FLAGS_SEQ           0x1000   /* sequence number present */
#define ERSPAN_TYPE_I_PROTO     0x6558   /* transparent Ethernet bridging */
#define ERSPAN_TYPE_II_PROTO    0x88BE   /* ERSPAN Type II */
#define ERSPAN_TYPE_III_PROTO   0x22EB   /* ERSPAN Type III */

/* Header sizes */
#define ETH_HDR_SIZE            14
#define GRE_HDR_BASE_SIZE       4        /* flags(2) + proto(2) */
#define GRE_SEQ_SIZE            4        /* sequence number field */
#define ERSPAN_II_HDR_SIZE      8
#define ERSPAN_III_HDR_SIZE     12

/* ERSPAN session ID max (10-bit field) */
#define ERSPAN_MAX_SESSION_ID   1023

#define MAX_ERSPAN_TRANSPORTS   10
#define MAX_ERSPAN_PACKET       65535

/* GRE base header (4 bytes) */
typedef struct gre_hdr {
    uint16_t flags;
    uint16_t proto;
} __attribute__((packed)) gre_hdr_t;

/* ERSPAN Type II header (8 bytes) */
typedef struct erspan_ii_hdr {
    uint16_t ver_vlan;   /* ver[15:12]=0001, vlan[11:0] */
    uint16_t cos_en_t_session; /* cos[15:13], en[12:11], T[10], session[9:0] */
    uint32_t reserved_index; /* reserved[31:20], index[19:0] */
} __attribute__((packed)) erspan_ii_hdr_t;

/* ERSPAN Type III header (12 bytes — 3 x 32-bit words per Cisco draft) */
typedef struct erspan_iii_hdr {
    uint16_t ver_vlan;        /* ver[15:12]=0011, vlan[11:0] */
    uint16_t cos_bso_t_sid;   /* cos[15:13], bso[12:11], T[10], session_id[9:0] */
    uint32_t timestamp;
    uint16_t sgt;
    uint16_t p_ft_hw_d_gra_o; /* p[15], ft[14:10], hw[9:6], d[5], gra[4:3], o[2:0] */
} __attribute__((packed)) erspan_iii_hdr_t;

/* Synthetic inner Ethernet header for non-pcap paths */
typedef struct synth_eth_hdr {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t ethertype; /* 0x0800 = IPv4 */
} __attribute__((packed)) synth_eth_hdr_t;

/* Portable IPv4 header (avoids Linux struct iphdr vs BSD struct ip portability) */
typedef struct erspan_ipv4_hdr {
    uint8_t  ver_ihl;    /* version[7:4] + IHL[3:0] */
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
} __attribute__((packed)) erspan_ipv4_hdr_t;

/* Portable UDP header */
typedef struct erspan_udp_hdr {
    uint16_t sport;
    uint16_t dport;
    uint16_t len;
    uint16_t check;
} __attribute__((packed)) erspan_udp_hdr_t;

/* Per-profile config */
typedef struct profile_erspan {
    char     *name;
    char     *description;
    char     *capt_host;     /* destination IP */
    char     *src_host;      /* source IP for outer GRE envelope */
    uint8_t   erspan_version; /* 1, 2, or 3 */
    uint16_t  session_id;    /* 0–1023 */
    uint32_t  seq_num;       /* incremented per packet */
    int       raw_fd;        /* raw socket fd */
    int       enabled;
    struct profile_erspan *next;
} profile_erspan_t;

typedef struct transport_erspan_stats {
    uint64_t received_packets_total;
    uint64_t send_packets_total;
    uint64_t errors_total;
} transport_erspan_stats_t;

extern char *global_config_path;

int  load_module_xml_config(void);
void free_module_xml_config(void);
int  reload_config(char *erbuf, int erlen);
int  bind_usrloc(transport_module_api_t *api);
int  send_erspan(msg_t *msg);
int  w_send_erspan_api(msg_t *_m, char *param1);

#endif /* _TRANSPORT_ERSPAN_H_ */
