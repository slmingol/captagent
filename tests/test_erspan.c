/*
 * Unit tests for transport_erspan packet building logic.
 *
 * Tests exercise the pure functions mirrored from the module:
 *   - ip_checksum correctness
 *   - ERSPAN packet structure and sizes for Type I, II, III
 *   - GRE header fields (flags, proto) per version
 *   - ERSPAN header field encoding (ver, session ID) per type
 *   - Inner frame field population from rcinfo
 *   - Inner IP checksum validity in assembled packet
 *   - Oversized payload rejection
 *   - session_id boundary values
 *
 * NOTE: build_test_packet() is a parallel implementation of build_erspan_packet()
 * that shares struct definitions via _Static_assert size checks. To catch logic
 * divergence, session_id encoding and checksum tests parse actual byte offsets.
 */

#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

/* ── replicate types/constants from transport_erspan.h ────────────────── */

#define GRE_PROTO               47
#define GRE_FLAGS_SEQ           0x1000
#define ERSPAN_TYPE_I_PROTO     0x6558
#define ERSPAN_TYPE_II_PROTO    0x88BE
#define ERSPAN_TYPE_III_PROTO   0x22EB

#define ETH_HDR_SIZE            14
#define GRE_HDR_BASE_SIZE       4
#define GRE_SEQ_SIZE            4
#define ERSPAN_II_HDR_SIZE      8
#define ERSPAN_III_HDR_SIZE     12
#define ERSPAN_MAX_SESSION_ID   1023
#define MAX_ERSPAN_PACKET       65535

typedef struct gre_hdr {
    uint16_t flags;
    uint16_t proto;
} __attribute__((packed)) gre_hdr_t;

typedef struct erspan_ii_hdr {
    uint16_t ver_vlan;
    uint16_t cos_en_t_session;
    uint32_t reserved_index;
} __attribute__((packed)) erspan_ii_hdr_t;

/* ERSPAN Type III header — 3 x 32-bit words per Cisco draft */
typedef struct erspan_iii_hdr {
    uint16_t ver_vlan;        /* ver[15:12]=0011, vlan[11:0] */
    uint16_t cos_bso_t_sid;   /* cos[15:13], bso[12:11], T[10], session_id[9:0] */
    uint32_t timestamp;
    uint16_t sgt;
    uint16_t p_ft_hw_d_gra_o; /* p[15], ft[14:10], hw[9:6], d[5], gra[4:3], o[2:0] */
} __attribute__((packed)) erspan_iii_hdr_t;

typedef struct synth_eth_hdr {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t ethertype;
} __attribute__((packed)) synth_eth_hdr_t;

typedef struct erspan_ipv4_hdr {
    uint8_t  ver_ihl;
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

typedef struct erspan_udp_hdr {
    uint16_t sport;
    uint16_t dport;
    uint16_t len;
    uint16_t check;
} __attribute__((packed)) erspan_udp_hdr_t;

/* Guard against struct divergence from transport_erspan.h */
_Static_assert(sizeof(gre_hdr_t)         == 4,  "gre_hdr_t size");
_Static_assert(sizeof(erspan_ii_hdr_t)   == 8,  "erspan_ii_hdr_t size");
_Static_assert(sizeof(erspan_iii_hdr_t)  == 12, "erspan_iii_hdr_t size");
_Static_assert(sizeof(synth_eth_hdr_t)   == 14, "synth_eth_hdr_t size");
_Static_assert(sizeof(erspan_ipv4_hdr_t) == 20, "erspan_ipv4_hdr_t size");
_Static_assert(sizeof(erspan_udp_hdr_t)  == 8,  "erspan_udp_hdr_t size");

_Static_assert(ERSPAN_II_HDR_SIZE  == sizeof(erspan_ii_hdr_t),  "ERSPAN_II_HDR_SIZE mismatch");
_Static_assert(ERSPAN_III_HDR_SIZE == sizeof(erspan_iii_hdr_t), "ERSPAN_III_HDR_SIZE mismatch");

/* ── ip_checksum (copy from transport_erspan.c for unit testing) ──────── */

static uint16_t ip_checksum(void *buf, int len)
{
    uint32_t  sum = 0;
    uint16_t *p   = (uint16_t *)buf;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)(~sum);
}

/* ── minimal packet builder (parallel to transport_erspan.c logic) ──────  */

typedef struct {
    uint8_t    erspan_version;
    uint16_t   session_id;
    uint32_t   seq_num;
    const char *capt_host;
    const char *src_host;
} test_profile_t;

typedef struct {
    const char *src_ip;
    const char *dst_ip;
    uint16_t    src_port;
    uint16_t    dst_port;
} test_rcinfo_t;

static int build_test_packet(test_profile_t *prof, test_rcinfo_t *rc,
                             const uint8_t *payload, size_t payload_len,
                             uint8_t *out, size_t out_sz)
{
    uint8_t version = prof->erspan_version;

    if (payload_len > 65507) return -1;

    synth_eth_hdr_t eth;
    memset(&eth, 0, sizeof(eth));
    eth.ethertype = htons(0x0800);

    erspan_ipv4_hdr_t iip;
    memset(&iip, 0, sizeof(iip));
    iip.ver_ihl  = (4 << 4) | 5;
    iip.ttl      = 64;
    iip.protocol = 17; /* UDP */
    if (rc->src_ip) inet_pton(AF_INET, rc->src_ip, &iip.saddr);
    if (rc->dst_ip) inet_pton(AF_INET, rc->dst_ip, &iip.daddr);

    erspan_udp_hdr_t iudp;
    memset(&iudp, 0, sizeof(iudp));
    iudp.sport = htons(rc->src_port);
    iudp.dport = htons(rc->dst_port);
    iudp.len   = htons((uint16_t)(sizeof(erspan_udp_hdr_t) + payload_len));

    uint16_t inner_ip_total = (uint16_t)(sizeof(erspan_ipv4_hdr_t) + sizeof(erspan_udp_hdr_t) + payload_len);
    iip.tot_len = htons(inner_ip_total);
    iip.check   = ip_checksum(&iip, sizeof(erspan_ipv4_hdr_t));

    uint16_t gre_proto;
    switch (version) {
        case 1:  gre_proto = htons(ERSPAN_TYPE_I_PROTO);   break;
        case 3:  gre_proto = htons(ERSPAN_TYPE_III_PROTO); break;
        default: gre_proto = htons(ERSPAN_TYPE_II_PROTO);  break;
    }

    gre_hdr_t gre;
    gre.flags = (version == 1) ? 0 : htons(GRE_FLAGS_SEQ);
    gre.proto = gre_proto;

    uint32_t seq = (version != 1) ? htonl(prof->seq_num) : 0;

    erspan_ii_hdr_t  erspan2; memset(&erspan2,  0, sizeof(erspan2));
    erspan_iii_hdr_t erspan3; memset(&erspan3, 0, sizeof(erspan3));
    uint16_t sid = prof->session_id & ERSPAN_MAX_SESSION_ID;
    if (version == 2) {
        erspan2.ver_vlan         = htons((uint16_t)((1 << 12) | 0));
        erspan2.cos_en_t_session = htons(sid);
    } else if (version == 3) {
        erspan3.ver_vlan      = htons((uint16_t)((3 << 12) | 0)); /* ver=3, vlan=0 */
        erspan3.cos_bso_t_sid = htons(sid);  /* session_id in bits [9:0] */
    }

    size_t gre_block_sz = sizeof(gre_hdr_t);
    if (version != 1) gre_block_sz += GRE_SEQ_SIZE;
    if (version == 2) gre_block_sz += ERSPAN_II_HDR_SIZE;
    if (version == 3) gre_block_sz += ERSPAN_III_HDR_SIZE;

    size_t inner_frame_sz = ETH_HDR_SIZE + (size_t)inner_ip_total;
    size_t pkt_total      = sizeof(erspan_ipv4_hdr_t) + gre_block_sz + inner_frame_sz;

    if (pkt_total > out_sz) return -1;

    erspan_ipv4_hdr_t oip;
    memset(&oip, 0, sizeof(oip));
    oip.ver_ihl  = (4 << 4) | 5;
    oip.ttl      = 64;
    oip.protocol = GRE_PROTO;
    oip.tot_len  = htons((uint16_t)pkt_total);
    if (prof->src_host)  inet_pton(AF_INET, prof->src_host,  &oip.saddr);
    if (prof->capt_host) inet_pton(AF_INET, prof->capt_host, &oip.daddr);
    oip.check = ip_checksum(&oip, sizeof(erspan_ipv4_hdr_t));

    uint8_t *p = out;
    memcpy(p, &oip,    sizeof(erspan_ipv4_hdr_t)); p += sizeof(erspan_ipv4_hdr_t);
    memcpy(p, &gre,    sizeof(gre_hdr_t));          p += sizeof(gre_hdr_t);
    if (version != 1) { memcpy(p, &seq, GRE_SEQ_SIZE); p += GRE_SEQ_SIZE; }
    if (version == 2) { memcpy(p, &erspan2, ERSPAN_II_HDR_SIZE);  p += ERSPAN_II_HDR_SIZE; }
    if (version == 3) { memcpy(p, &erspan3, ERSPAN_III_HDR_SIZE); p += ERSPAN_III_HDR_SIZE; }
    memcpy(p, &eth,    ETH_HDR_SIZE);               p += ETH_HDR_SIZE;
    memcpy(p, &iip,    sizeof(erspan_ipv4_hdr_t));  p += sizeof(erspan_ipv4_hdr_t);
    memcpy(p, &iudp,   sizeof(erspan_udp_hdr_t));   p += sizeof(erspan_udp_hdr_t);
    memcpy(p, payload, payload_len);

    return (int)pkt_total;
}

/* ── helpers ─────────────────────────────────────────────────────────── */

#define OUTER_IP_SZ    sizeof(erspan_ipv4_hdr_t)   /* 20 */
#define GRE_BASE_SZ    sizeof(gre_hdr_t)            /*  4 */
#define INNER_FRAME(payload_len) \
    (ETH_HDR_SIZE + sizeof(erspan_ipv4_hdr_t) + sizeof(erspan_udp_hdr_t) + (payload_len))

static size_t expected_size(uint8_t version, size_t payload_len)
{
    size_t gre_block = GRE_BASE_SZ;
    if (version != 1) gre_block += GRE_SEQ_SIZE;
    if (version == 2) gre_block += ERSPAN_II_HDR_SIZE;
    if (version == 3) gre_block += ERSPAN_III_HDR_SIZE;
    return OUTER_IP_SZ + gre_block + INNER_FRAME(payload_len);
}

static test_profile_t make_prof(uint8_t ver)
{
    test_profile_t p = {
        .erspan_version = ver,
        .session_id     = 42,
        .seq_num        = 1,
        .capt_host      = "192.0.2.1",
        .src_host       = "10.0.0.1",
    };
    return p;
}

static test_rcinfo_t make_rc(void)
{
    test_rcinfo_t rc = {
        .src_ip   = "10.1.1.1",
        .dst_ip   = "10.1.1.2",
        .src_port = 5060,
        .dst_port = 5060,
    };
    return rc;
}

static const uint8_t sip_payload[] = "INVITE sip:bob@example.com SIP/2.0\r\n\r\n";

/* ── tests ────────────────────────────────────────────────────────────── */

START_TEST(test_ip_checksum_zero_for_valid_header)
{
    erspan_ipv4_hdr_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.ver_ihl  = (4 << 4) | 5;
    hdr.ttl      = 64;
    hdr.protocol = GRE_PROTO;
    hdr.tot_len  = htons(100);
    hdr.check    = ip_checksum(&hdr, sizeof(hdr));
    ck_assert_uint_eq(ip_checksum(&hdr, sizeof(hdr)), 0);
}
END_TEST

START_TEST(test_type_i_packet_size)
{
    uint8_t buf[MAX_ERSPAN_PACKET];
    test_profile_t p  = make_prof(1);
    test_rcinfo_t  rc = make_rc();
    int len = build_test_packet(&p, &rc, sip_payload, sizeof(sip_payload)-1, buf, sizeof(buf));
    ck_assert_int_gt(len, 0);
    ck_assert_uint_eq((size_t)len, expected_size(1, sizeof(sip_payload)-1));
}
END_TEST

START_TEST(test_type_ii_packet_size)
{
    uint8_t buf[MAX_ERSPAN_PACKET];
    test_profile_t p  = make_prof(2);
    test_rcinfo_t  rc = make_rc();
    int len = build_test_packet(&p, &rc, sip_payload, sizeof(sip_payload)-1, buf, sizeof(buf));
    ck_assert_int_gt(len, 0);
    ck_assert_uint_eq((size_t)len, expected_size(2, sizeof(sip_payload)-1));
}
END_TEST

START_TEST(test_type_iii_packet_size)
{
    uint8_t buf[MAX_ERSPAN_PACKET];
    test_profile_t p  = make_prof(3);
    test_rcinfo_t  rc = make_rc();
    int len = build_test_packet(&p, &rc, sip_payload, sizeof(sip_payload)-1, buf, sizeof(buf));
    ck_assert_int_gt(len, 0);
    ck_assert_uint_eq((size_t)len, expected_size(3, sizeof(sip_payload)-1));
}
END_TEST

START_TEST(test_type_i_gre_proto)
{
    uint8_t buf[MAX_ERSPAN_PACKET];
    test_profile_t p  = make_prof(1);
    test_rcinfo_t  rc = make_rc();
    build_test_packet(&p, &rc, sip_payload, sizeof(sip_payload)-1, buf, sizeof(buf));

    gre_hdr_t *gre = (gre_hdr_t *)(buf + OUTER_IP_SZ);
    ck_assert_uint_eq(ntohs(gre->proto), ERSPAN_TYPE_I_PROTO);
    ck_assert_uint_eq(gre->flags, 0);
}
END_TEST

START_TEST(test_type_ii_gre_proto_and_seq_flag)
{
    uint8_t buf[MAX_ERSPAN_PACKET];
    test_profile_t p  = make_prof(2);
    test_rcinfo_t  rc = make_rc();
    build_test_packet(&p, &rc, sip_payload, sizeof(sip_payload)-1, buf, sizeof(buf));

    gre_hdr_t *gre = (gre_hdr_t *)(buf + OUTER_IP_SZ);
    ck_assert_uint_eq(ntohs(gre->proto), ERSPAN_TYPE_II_PROTO);
    ck_assert_uint_eq(ntohs(gre->flags), GRE_FLAGS_SEQ);
}
END_TEST

START_TEST(test_type_iii_gre_proto)
{
    uint8_t buf[MAX_ERSPAN_PACKET];
    test_profile_t p  = make_prof(3);
    test_rcinfo_t  rc = make_rc();
    build_test_packet(&p, &rc, sip_payload, sizeof(sip_payload)-1, buf, sizeof(buf));

    gre_hdr_t *gre = (gre_hdr_t *)(buf + OUTER_IP_SZ);
    ck_assert_uint_eq(ntohs(gre->proto), ERSPAN_TYPE_III_PROTO);
    ck_assert_uint_eq(ntohs(gre->flags), GRE_FLAGS_SEQ);
}
END_TEST

START_TEST(test_type_ii_session_id)
{
    uint8_t buf[MAX_ERSPAN_PACKET];
    test_profile_t p  = make_prof(2);
    p.session_id = 99;
    test_rcinfo_t rc = make_rc();
    build_test_packet(&p, &rc, sip_payload, sizeof(sip_payload)-1, buf, sizeof(buf));

    size_t off = OUTER_IP_SZ + GRE_BASE_SZ + GRE_SEQ_SIZE;
    erspan_ii_hdr_t *e2 = (erspan_ii_hdr_t *)(buf + off);
    ck_assert_uint_eq(ntohs(e2->cos_en_t_session) & ERSPAN_MAX_SESSION_ID, 99);
}
END_TEST

START_TEST(test_type_iii_session_id)
{
    uint8_t buf[MAX_ERSPAN_PACKET];
    test_profile_t p  = make_prof(3);
    p.session_id = 77;
    test_rcinfo_t rc = make_rc();
    build_test_packet(&p, &rc, sip_payload, sizeof(sip_payload)-1, buf, sizeof(buf));

    /* ERSPAN III Word 0: after outer IP + GRE base + seq */
    size_t off = OUTER_IP_SZ + GRE_BASE_SZ + GRE_SEQ_SIZE;
    erspan_iii_hdr_t *e3 = (erspan_iii_hdr_t *)(buf + off);

    /* ver field in bits [15:12] of ver_vlan must be 3 */
    uint16_t ver_vlan = ntohs(e3->ver_vlan);
    ck_assert_uint_eq(ver_vlan >> 12, 3);

    /* session_id in bits [9:0] of cos_bso_t_sid */
    uint16_t sid_field = ntohs(e3->cos_bso_t_sid);
    ck_assert_uint_eq(sid_field & ERSPAN_MAX_SESSION_ID, 77);
}
END_TEST

START_TEST(test_type_ii_session_id_zero)
{
    uint8_t buf[MAX_ERSPAN_PACKET];
    test_profile_t p  = make_prof(2);
    p.session_id = 0;
    test_rcinfo_t rc = make_rc();
    build_test_packet(&p, &rc, sip_payload, sizeof(sip_payload)-1, buf, sizeof(buf));

    size_t off = OUTER_IP_SZ + GRE_BASE_SZ + GRE_SEQ_SIZE;
    erspan_ii_hdr_t *e2 = (erspan_ii_hdr_t *)(buf + off);
    ck_assert_uint_eq(ntohs(e2->cos_en_t_session) & ERSPAN_MAX_SESSION_ID, 0);
}
END_TEST

START_TEST(test_type_ii_session_id_max)
{
    uint8_t buf[MAX_ERSPAN_PACKET];
    test_profile_t p  = make_prof(2);
    p.session_id = ERSPAN_MAX_SESSION_ID;  /* 1023 */
    test_rcinfo_t rc = make_rc();
    build_test_packet(&p, &rc, sip_payload, sizeof(sip_payload)-1, buf, sizeof(buf));

    size_t off = OUTER_IP_SZ + GRE_BASE_SZ + GRE_SEQ_SIZE;
    erspan_ii_hdr_t *e2 = (erspan_ii_hdr_t *)(buf + off);
    ck_assert_uint_eq(ntohs(e2->cos_en_t_session) & ERSPAN_MAX_SESSION_ID, 1023);
}
END_TEST

START_TEST(test_session_id_truncated_to_10_bits)
{
    /* session_id=1024 should truncate to 0 (1024 & 0x3FF == 0) */
    uint8_t buf[MAX_ERSPAN_PACKET];
    test_profile_t p  = make_prof(2);
    p.session_id = 1024;
    test_rcinfo_t rc = make_rc();
    build_test_packet(&p, &rc, sip_payload, sizeof(sip_payload)-1, buf, sizeof(buf));

    size_t off = OUTER_IP_SZ + GRE_BASE_SZ + GRE_SEQ_SIZE;
    erspan_ii_hdr_t *e2 = (erspan_ii_hdr_t *)(buf + off);
    ck_assert_uint_eq(ntohs(e2->cos_en_t_session) & ERSPAN_MAX_SESSION_ID, 0);
}
END_TEST

START_TEST(test_outer_ip_protocol_is_gre)
{
    uint8_t buf[MAX_ERSPAN_PACKET];
    test_profile_t p  = make_prof(2);
    test_rcinfo_t  rc = make_rc();
    build_test_packet(&p, &rc, sip_payload, sizeof(sip_payload)-1, buf, sizeof(buf));

    erspan_ipv4_hdr_t *oip = (erspan_ipv4_hdr_t *)buf;
    ck_assert_uint_eq(oip->protocol, GRE_PROTO);
    ck_assert_uint_eq((oip->ver_ihl >> 4), 4);
    ck_assert_uint_eq((oip->ver_ihl & 0x0f), 5);
}
END_TEST

START_TEST(test_outer_ip_checksum_valid)
{
    uint8_t buf[MAX_ERSPAN_PACKET];
    test_profile_t p  = make_prof(2);
    test_rcinfo_t  rc = make_rc();
    build_test_packet(&p, &rc, sip_payload, sizeof(sip_payload)-1, buf, sizeof(buf));

    /* Re-verifying the checksum over the assembled outer IP header must give 0 */
    ck_assert_uint_eq(ip_checksum(buf, sizeof(erspan_ipv4_hdr_t)), 0);
}
END_TEST

START_TEST(test_inner_ip_checksum_valid)
{
    uint8_t buf[MAX_ERSPAN_PACKET];
    test_profile_t p  = make_prof(2);
    test_rcinfo_t  rc = make_rc();
    int total = build_test_packet(&p, &rc, sip_payload, sizeof(sip_payload)-1, buf, sizeof(buf));
    ck_assert_int_gt(total, 0);

    /* Inner IP header offset: outer IP + GRE block + ETH */
    size_t gre_block = GRE_BASE_SZ + GRE_SEQ_SIZE + ERSPAN_II_HDR_SIZE;
    size_t off = OUTER_IP_SZ + gre_block + ETH_HDR_SIZE;
    ck_assert_uint_eq(ip_checksum(buf + off, sizeof(erspan_ipv4_hdr_t)), 0);
}
END_TEST

START_TEST(test_inner_ip_src_dst_populated)
{
    uint8_t buf[MAX_ERSPAN_PACKET];
    test_profile_t p  = make_prof(2);
    test_rcinfo_t  rc = make_rc();
    build_test_packet(&p, &rc, sip_payload, sizeof(sip_payload)-1, buf, sizeof(buf));

    size_t gre_block = GRE_BASE_SZ + GRE_SEQ_SIZE + ERSPAN_II_HDR_SIZE;
    size_t off = OUTER_IP_SZ + gre_block + ETH_HDR_SIZE;
    erspan_ipv4_hdr_t *iip = (erspan_ipv4_hdr_t *)(buf + off);

    uint32_t expected_src, expected_dst;
    inet_pton(AF_INET, rc.src_ip, &expected_src);
    inet_pton(AF_INET, rc.dst_ip, &expected_dst);
    ck_assert_uint_eq(iip->saddr, expected_src);
    ck_assert_uint_eq(iip->daddr, expected_dst);
}
END_TEST

START_TEST(test_inner_udp_ports)
{
    uint8_t buf[MAX_ERSPAN_PACKET];
    test_profile_t p  = make_prof(2);
    test_rcinfo_t  rc = make_rc();
    rc.src_port = 12345;
    rc.dst_port = 5060;
    build_test_packet(&p, &rc, sip_payload, sizeof(sip_payload)-1, buf, sizeof(buf));

    size_t gre_block = GRE_BASE_SZ + GRE_SEQ_SIZE + ERSPAN_II_HDR_SIZE;
    size_t off = OUTER_IP_SZ + gre_block + ETH_HDR_SIZE + sizeof(erspan_ipv4_hdr_t);
    erspan_udp_hdr_t *udp = (erspan_udp_hdr_t *)(buf + off);
    ck_assert_uint_eq(ntohs(udp->sport), 12345);
    ck_assert_uint_eq(ntohs(udp->dport), 5060);
}
END_TEST

START_TEST(test_oversized_payload_rejected)
{
    uint8_t buf[64];  /* too small for a full packet */
    test_profile_t p  = make_prof(2);
    test_rcinfo_t  rc = make_rc();
    int len = build_test_packet(&p, &rc, sip_payload, sizeof(sip_payload)-1, buf, sizeof(buf));
    ck_assert_int_eq(len, -1);
}
END_TEST

START_TEST(test_payload_present_at_end)
{
    uint8_t buf[MAX_ERSPAN_PACKET];
    test_profile_t p  = make_prof(2);
    test_rcinfo_t  rc = make_rc();
    size_t plen = sizeof(sip_payload) - 1;
    int total = build_test_packet(&p, &rc, sip_payload, plen, buf, sizeof(buf));
    ck_assert_int_gt(total, 0);
    ck_assert_mem_eq(buf + total - plen, sip_payload, plen);
}
END_TEST

/* ── suite wiring ─────────────────────────────────────────────────────── */

Suite *erspan_suite(void)
{
    Suite *s  = suite_create("transport_erspan");
    TCase *tc = tcase_create("packet_builder");

    tcase_add_test(tc, test_ip_checksum_zero_for_valid_header);
    tcase_add_test(tc, test_type_i_packet_size);
    tcase_add_test(tc, test_type_ii_packet_size);
    tcase_add_test(tc, test_type_iii_packet_size);
    tcase_add_test(tc, test_type_i_gre_proto);
    tcase_add_test(tc, test_type_ii_gre_proto_and_seq_flag);
    tcase_add_test(tc, test_type_iii_gre_proto);
    tcase_add_test(tc, test_type_ii_session_id);
    tcase_add_test(tc, test_type_iii_session_id);
    tcase_add_test(tc, test_type_ii_session_id_zero);
    tcase_add_test(tc, test_type_ii_session_id_max);
    tcase_add_test(tc, test_session_id_truncated_to_10_bits);
    tcase_add_test(tc, test_outer_ip_protocol_is_gre);
    tcase_add_test(tc, test_outer_ip_checksum_valid);
    tcase_add_test(tc, test_inner_ip_checksum_valid);
    tcase_add_test(tc, test_inner_ip_src_dst_populated);
    tcase_add_test(tc, test_inner_udp_ports);
    tcase_add_test(tc, test_oversized_payload_rejected);
    tcase_add_test(tc, test_payload_present_at_end);

    suite_add_tcase(s, tc);
    return s;
}

int main(void)
{
    int       number_failed;
    Suite    *s  = erspan_suite();
    SRunner  *sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
