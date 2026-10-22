/*
 * captagent - Homer capture agent. Modular
 * ERSPAN/GRE transport module
 *
 * Sends captured SIP/RTP encapsulated in GRE or ERSPAN (Type I/II/III) via
 * raw socket. Ativa probes reassemble fragmented GRE/ERSPAN at the network
 * layer, avoiding the HEP/UDP fragmentation drop problem.
 *
 * Wire formats:
 *   Type I:   [outer IP][GRE 4B][inner Eth][inner IP][UDP][SIP]
 *   Type II:  [outer IP][GRE 4B][SeqNum 4B][ERSPAN-II 8B][inner Eth][inner IP][UDP][SIP]
 *   Type III: [outer IP][GRE 4B][SeqNum 4B][ERSPAN-III 12B][inner Eth][inner IP][UDP][SIP]
 *
 * For non-pcap paths (Ribbon monitoring profile raw SIP), a synthetic inner
 * Ethernet+IP+UDP frame is constructed from rcinfo src_ip/dst_ip/ports.
 *
 * Author: slmingol
 * License: GPLv3
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>

#include "config.h"

#include <captagent/api.h>
#include <captagent/proto_sip.h>
#include <captagent/structure.h>
#include <captagent/modules_api.h>
#include <captagent/modules.h>
#include "transport_erspan.h"
#include <captagent/log.h>

xml_node *module_xml_config = NULL;
char     *module_name        = "transport_erspan";
uint64_t  module_serial      = 0;
char     *module_description = NULL;

static profile_erspan_t        profile_erspan[MAX_ERSPAN_TRANSPORTS];
static unsigned int            profile_size = 0;
static transport_erspan_stats_t stats;

/* forward declarations */
static int load_module(xml_node *config);
static int unload_module(void);
static int description(char *descr);
static int statistic(char *buf, size_t len);
static uint64_t serial_module(void);

static cmd_export_t cmds[] = {
    { "transport_erspan_bind_api", (cmd_function)bind_usrloc,       1, 0, 0, 0 },
    { "send_erspan",               (cmd_function)w_send_erspan_api, 1, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0 }
};

struct module_exports exports = {
    "transport_erspan",
    cmds,
    load_module,
    unload_module,
    description,
    statistic,
    serial_module
};

/* ── checksum helper ──────────────────────────────────────────────────── */

static uint16_t ip_checksum(void *buf, int len)
{
    uint32_t  sum = 0;
    uint16_t *p   = (uint16_t *)buf;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)(~sum);
}

/* ── raw socket init ──────────────────────────────────────────────────── */

static int init_raw_socket(unsigned int idx)
{
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_GRE);
    if (fd < 0) {
        LERR("transport_erspan[%s]: socket(RAW,GRE) failed: %s",
             profile_erspan[idx].name, strerror(errno));
        return -1;
    }
    int on = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        LERR("transport_erspan[%s]: IP_HDRINCL failed: %s",
             profile_erspan[idx].name, strerror(errno));
        close(fd);
        return -1;
    }
    profile_erspan[idx].raw_fd = fd;
    LDEBUG("transport_erspan[%s]: raw socket %d opened", profile_erspan[idx].name, fd);
    return 0;
}

/* ── packet builder ───────────────────────────────────────────────────── */

/*
 * Build GRE/ERSPAN packet into `out`.
 * Returns total byte count written, or -1 on error.
 *
 * Inner frame is a synthetic Ethernet+IP+UDP wrapper around the SIP payload.
 * src_ip/dst_ip come from rcinfo (the original SBC endpoints) so Ativa sees
 * the correct signalling addresses.
 */
static int build_erspan_packet(unsigned int idx, msg_t *msg,
                               uint8_t *out, size_t out_sz)
{
    rc_info_t *rcinfo = &msg->rcinfo;
    uint8_t    version = profile_erspan[idx].erspan_version;

    /* ---- synthetic inner Ethernet header ---- */
    synth_eth_hdr_t eth;
    memset(&eth, 0, sizeof(eth));
    eth.ethertype = htons(0x0800);  /* IPv4 */

    /* ---- synthetic inner IP header (portable) ---- */
    erspan_ipv4_hdr_t iip;
    memset(&iip, 0, sizeof(iip));
    iip.ver_ihl  = (4 << 4) | 5;   /* version=4, IHL=5 (20 bytes) */
    iip.ttl      = 64;
    iip.protocol = IPPROTO_UDP;
    if (rcinfo->src_ip) inet_pton(AF_INET, rcinfo->src_ip, &iip.saddr);
    if (rcinfo->dst_ip) inet_pton(AF_INET, rcinfo->dst_ip, &iip.daddr);

    /*
     * Payload must fit in the assembled packet. Conservative bound is the
     * Type III max: 65535 - 20(outer IP) - 4(GRE) - 4(seq) - 12(ERSPAN-III)
     * - 14(eth) - 20(inner IP) - 8(inner UDP) = 65453. Safe for all types.
     */
    if (msg->len > 65453) {
        LERR("transport_erspan[%s]: payload %zu > 65453 — dropping",
             profile_erspan[idx].name, msg->len);
        return -1;
    }

    /* ---- synthetic inner UDP header (portable) ---- */
    erspan_udp_hdr_t iudp;
    memset(&iudp, 0, sizeof(iudp));
    iudp.sport = htons(rcinfo->src_port);
    iudp.dport = htons(rcinfo->dst_port);
    iudp.len   = htons((uint16_t)(sizeof(erspan_udp_hdr_t) + msg->len));

    uint16_t inner_ip_total = (uint16_t)(sizeof(erspan_ipv4_hdr_t) + sizeof(erspan_udp_hdr_t) + msg->len);
    iip.tot_len = htons(inner_ip_total);
    iip.check   = ip_checksum(&iip, sizeof(erspan_ipv4_hdr_t));

    /* ---- GRE header ---- */
    uint16_t gre_proto;
    switch (version) {
        case 1:  gre_proto = htons(ERSPAN_TYPE_I_PROTO);   break;
        case 3:  gre_proto = htons(ERSPAN_TYPE_III_PROTO); break;
        default: gre_proto = htons(ERSPAN_TYPE_II_PROTO);  break;
    }

    gre_hdr_t gre;
    memset(&gre, 0, sizeof(gre));
    gre.flags = (version == 1) ? 0 : htons(GRE_FLAGS_SEQ);
    gre.proto = gre_proto;

    /* Type I has no sequence field on the wire; only increment for II/III */
    uint32_t seq = (version != 1)
        ? htonl(__sync_fetch_and_add(&profile_erspan[idx].seq_num, 1))
        : 0;

    /* ---- ERSPAN type-specific header ---- */
    erspan_ii_hdr_t  erspan2;
    erspan_iii_hdr_t erspan3;
    memset(&erspan2, 0, sizeof(erspan2));
    memset(&erspan3, 0, sizeof(erspan3));

    uint16_t sid = profile_erspan[idx].session_id & ERSPAN_MAX_SESSION_ID;

    if (version == 2) {
        erspan2.ver_vlan         = htons((uint16_t)((1 << 12) | 0));  /* ver=1, vlan=0 */
        erspan2.cos_en_t_session = htons(sid);
        erspan2.reserved_index   = 0;
    } else if (version == 3) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        erspan3.ver_vlan      = htons((uint16_t)((3 << 12) | 0)); /* ver=3, vlan=0 */
        erspan3.cos_bso_t_sid = htons(sid);  /* session_id in bits [9:0] */
        erspan3.timestamp     = htonl((uint32_t)ts.tv_sec);
        erspan3.sgt           = 0;
        erspan3.p_ft_hw_d_gra_o = 0;
    }

    /* ---- calculate total size ---- */
    size_t gre_block_sz = sizeof(gre_hdr_t);
    if (version != 1) gre_block_sz += GRE_SEQ_SIZE;
    if (version == 2) gre_block_sz += ERSPAN_II_HDR_SIZE;
    if (version == 3) gre_block_sz += ERSPAN_III_HDR_SIZE;

    size_t inner_frame_sz = ETH_HDR_SIZE + (size_t)inner_ip_total;
    size_t pkt_total      = sizeof(erspan_ipv4_hdr_t) + gre_block_sz + inner_frame_sz;

    if (pkt_total > out_sz) {
        LERR("transport_erspan[%s]: packet %zu > buffer %zu — dropping",
             profile_erspan[idx].name, pkt_total, out_sz);
        return -1;
    }

    /* ---- outer IP header (portable) ---- */
    erspan_ipv4_hdr_t oip;
    memset(&oip, 0, sizeof(oip));
    oip.ver_ihl  = (4 << 4) | 5;
    oip.ttl      = 64;
    oip.protocol = GRE_PROTO;
    oip.tot_len  = htons((uint16_t)pkt_total);
    if (profile_erspan[idx].src_host)
        inet_pton(AF_INET, profile_erspan[idx].src_host, &oip.saddr);
    if (profile_erspan[idx].capt_host)
        inet_pton(AF_INET, profile_erspan[idx].capt_host, &oip.daddr);
    oip.check = ip_checksum(&oip, sizeof(erspan_ipv4_hdr_t));

    /* ---- assemble ---- */
    uint8_t *p = out;
    memcpy(p, &oip,  sizeof(erspan_ipv4_hdr_t)); p += sizeof(erspan_ipv4_hdr_t);
    memcpy(p, &gre,  sizeof(gre_hdr_t));          p += sizeof(gre_hdr_t);
    if (version != 1) { memcpy(p, &seq, GRE_SEQ_SIZE); p += GRE_SEQ_SIZE; }
    if (version == 2) { memcpy(p, &erspan2, ERSPAN_II_HDR_SIZE);  p += ERSPAN_II_HDR_SIZE; }
    if (version == 3) { memcpy(p, &erspan3, ERSPAN_III_HDR_SIZE); p += ERSPAN_III_HDR_SIZE; }
    memcpy(p, &eth,  ETH_HDR_SIZE);               p += ETH_HDR_SIZE;
    memcpy(p, &iip,  sizeof(erspan_ipv4_hdr_t));  p += sizeof(erspan_ipv4_hdr_t);
    memcpy(p, &iudp, sizeof(erspan_udp_hdr_t));   p += sizeof(erspan_udp_hdr_t);
    memcpy(p, msg->data, msg->len);

    return (int)pkt_total;
}

/* ── send path ────────────────────────────────────────────────────────── */

static int send_erspan_packet(unsigned int idx, msg_t *msg)
{
    uint8_t pkt[MAX_ERSPAN_PACKET];
    int     len = build_erspan_packet(idx, msg, pkt, sizeof(pkt));
    if (len < 0) { __sync_fetch_and_add(&stats.errors_total, 1); return -1; }

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    inet_pton(AF_INET, profile_erspan[idx].capt_host, &dst.sin_addr);

    ssize_t sent = sendto(profile_erspan[idx].raw_fd, pkt, (size_t)len, 0,
                          (struct sockaddr *)&dst, sizeof(dst));
    if (sent < 0 || (size_t)sent != (size_t)len) {
        LERR("transport_erspan[%s]: sendto failed (sent=%zd expected=%d): %s",
             profile_erspan[idx].name, sent, len, strerror(errno));
        __sync_fetch_and_add(&stats.errors_total, 1);
        return -1;
    }

    __sync_fetch_and_add(&stats.send_packets_total, 1);
    LDEBUG("transport_erspan[%s]: sent %zd bytes erspan-type=%u",
           profile_erspan[idx].name, sent, profile_erspan[idx].erspan_version);
    return 0;
}

/* ── public send API ──────────────────────────────────────────────────── */

int send_erspan(msg_t *msg)
{
    unsigned int i;
    if (!msg) return -1;

    __sync_fetch_and_add(&stats.received_packets_total, 1);

    char *pname = msg->profile_name ? msg->profile_name : "erspan";

    for (i = 0; i < profile_size; i++) {
        if (!profile_erspan[i].enabled) continue;
        if (strcmp(profile_erspan[i].name, pname) == 0)
            return send_erspan_packet(i, msg);
    }
    LERR("transport_erspan: no enabled profile named '%s'", pname);
    __sync_fetch_and_add(&stats.errors_total, 1);
    return -1;
}

int w_send_erspan_api(msg_t *_m, char *param1)
{
    if (param1) _m->profile_name = param1;
    return send_erspan(_m);
}

/* ── module API binding ───────────────────────────────────────────────── */

int bind_usrloc(transport_module_api_t *api)
{
    if (!api) { LERR("transport_erspan: null api"); return -1; }
    api->send_f      = send_erspan;
    api->reload_f    = reload_config;
    api->module_name = module_name;
    return 0;
}

/* ── XML config ───────────────────────────────────────────────────────── */

int load_module_xml_config(void)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s.xml", global_config_path, module_name);
    module_xml_config = xml_parse(path);
    if (!module_xml_config) {
        LERR("transport_erspan: failed to parse %s", path);
        return -1;
    }
    return 0;
}

void free_module_xml_config(void)
{
    if (module_xml_config) {
        xml_free(module_xml_config);
        module_xml_config = NULL;
    }
}

int reload_config(char *erbuf, int erlen)
{
    free_module_xml_config();
    if (load_module_xml_config() < 0) {
        snprintf(erbuf, erlen, "transport_erspan: reload failed");
        return -1;
    }
    return 0;
}

/* ── module lifecycle ─────────────────────────────────────────────────── */

static int load_module(xml_node *config)
{
    xml_node *profile, *settings, *param;
    char     *key, *value;
    unsigned int i;

    LNOTICE("Loaded %s", module_name);
    module_description = "GRE/ERSPAN (Type I/II/III) transport via raw socket";

    load_module_xml_config();

    profile_size = 0;
    memset(&stats, 0, sizeof(stats));
    profile = module_xml_config;

    while (profile) {
        profile = xml_get("profile", profile, 1);
        if (!profile) break;

        if (profile_size >= MAX_ERSPAN_TRANSPORTS) {
            LWARNING("transport_erspan: max %d profiles reached", MAX_ERSPAN_TRANSPORTS);
            break;
        }

        memset(&profile_erspan[profile_size], 0, sizeof(profile_erspan_t));
        profile_erspan[profile_size].raw_fd         = -1;
        profile_erspan[profile_size].erspan_version = 2;
        profile_erspan[profile_size].session_id     = 1;

        for (i = 0; profile->attr[i]; i += 2) {
            if (!strcmp(profile->attr[i], "name"))
                profile_erspan[profile_size].name = strdup(profile->attr[i+1]);
            else if (!strcmp(profile->attr[i], "description"))
                profile_erspan[profile_size].description = strdup(profile->attr[i+1]);
            else if (!strcmp(profile->attr[i], "enable"))
                profile_erspan[profile_size].enabled =
                    !strcasecmp(profile->attr[i+1], "true");
        }

        settings = xml_get("settings", profile, 1);
        if (settings) {
            param = settings;
            while ((param = xml_get("param", param, 1))) {
                key   = NULL;
                value = NULL;
                for (i = 0; param->attr[i]; i += 2) {
                    if (!strcmp(param->attr[i], "name"))  key   = param->attr[i+1];
                    if (!strcmp(param->attr[i], "value")) value = param->attr[i+1];
                }
                if (!key || !value) continue;

                if (!strcmp(key, "capture-host")) {
                    profile_erspan[profile_size].capt_host = strdup(value);
                } else if (!strcmp(key, "source-host")) {
                    profile_erspan[profile_size].src_host = strdup(value);
                } else if (!strcmp(key, "erspan-version")) {
                    int v = atoi(value);
                    if (v >= 1 && v <= 3)
                        profile_erspan[profile_size].erspan_version = (uint8_t)v;
                    else
                        LWARNING("transport_erspan: invalid erspan-version '%s', defaulting to 2", value);
                } else if (!strcmp(key, "session-id")) {
                    int s = atoi(value);
                    profile_erspan[profile_size].session_id =
                        (s >= 0 && s <= ERSPAN_MAX_SESSION_ID) ? (uint16_t)s : 1;
                }
            }
        }

        if (!profile_erspan[profile_size].capt_host) {
            LERR("transport_erspan[%s]: capture-host not set — skipping",
                 profile_erspan[profile_size].name ?: "(unnamed)");
            goto next_profile;
        }

        if (profile_erspan[profile_size].enabled) {
            if (init_raw_socket(profile_size) < 0) {
                LERR("transport_erspan[%s]: raw socket failed — disabling",
                     profile_erspan[profile_size].name);
                profile_erspan[profile_size].enabled = 0;
            }
        }

        LNOTICE("transport_erspan: profile '%s' erspan-type=%u dst=%s",
                profile_erspan[profile_size].name,
                profile_erspan[profile_size].erspan_version,
                profile_erspan[profile_size].capt_host);

        profile_size++;
        continue;

next_profile:
        free(profile_erspan[profile_size].name);
        free(profile_erspan[profile_size].description);
        free(profile_erspan[profile_size].capt_host);
        free(profile_erspan[profile_size].src_host);
    }

    free_module_xml_config();
    return 0;
}

static int unload_module(void)
{
    unsigned int i;
    LNOTICE("unloaded module transport_erspan");

    for (i = 0; i < profile_size; i++) {
        if (profile_erspan[i].raw_fd >= 0) {
            close(profile_erspan[i].raw_fd);
            profile_erspan[i].raw_fd = -1;
        }
        free(profile_erspan[i].name);         profile_erspan[i].name        = NULL;
        free(profile_erspan[i].description);  profile_erspan[i].description = NULL;
        free(profile_erspan[i].capt_host);    profile_erspan[i].capt_host   = NULL;
        free(profile_erspan[i].src_host);     profile_erspan[i].src_host    = NULL;
    }
    return 0;
}

static int description(char *descr)
{
    LNOTICE("Loaded description");
    descr = module_description;
    return 1;
}

static int statistic(char *buf, size_t len)
{
    int ret = 0;
    ret += snprintf(buf+ret, len-ret, "Total received: [%" PRId64 "]\r\n", stats.received_packets_total);
    ret += snprintf(buf+ret, len-ret, "Total sent:     [%" PRId64 "]\r\n", stats.send_packets_total);
    ret += snprintf(buf+ret, len-ret, "Errors total:   [%" PRId64 "]\r\n", stats.errors_total);
    return 1;
}

static uint64_t serial_module(void)
{
    return module_serial;
}
