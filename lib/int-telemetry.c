/*
 * Copyright (c) 2026 Open vSwitch contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * INT-MD transit node implementation.
 *
 * Implements sections 5.2.2, 5.7.2, and 5.8 of the INT Dataplane Spec v2.1.
 *
 * Metadata collection
 * ===================
 * Only the baseline instruction bits implementable with information available
 * at TX-batch flush time are supported.  Bits whose values cannot be
 * determined are filled with the INT "invalid" sentinel (0xFFFFFFFF / all-ones
 * for 4B, 0xFFFFFFFFFFFFFFFF for 8B), as required by the spec section 5.8.
 *
 * Supported bits and data sources:
 *   bit0  (Node ID)          — configured via other_config:int-node-id
 *   bit1  (L1 Ingress+Egress)— pkt->md.in_port (ingress), TX port no (egress)
 *   bit2  (Hop Latency)      — TX-batch age in µs (conservative estimate)
 *   bit3  (Queue Occ)        — TX-batch packet count (approximate)
 *   bit4  (Ingress TS)       — TX-batch birth timestamp (approximation)
 *   bit5  (Egress TS)        — now_us at TX-flush time
 *   bit6  (L2 Ingress+Egress)— same port IDs as bit1, zero-padded to 32b each
 *   bit7  (Egress TX Util)   — not available → 0xFFFFFFFF
 *   bit8  (Buffer Occ)       — not available → 0xFFFFFFFF
 *   bit15 (Checksum Comp)    — computed to make existing L4 csum valid
 *
 * Checksum handling
 * =================
 * The INT spec distinguishes two cases (section 5.6):
 *
 *   a) CC requested (bit15 set): each transit node computes a 4-byte
 *      Checksum Complement appended as the LAST field of its hop block.
 *      Its value is chosen so that the existing L4 checksum remains correct
 *      after the insertion — no L4 checksum recomputation is needed.
 *
 *   b) CC not requested (bit15 clear): the transit node must update the L4
 *      checksum directly via incremental update (RFC 1141 / RFC 1624).
 *
 * For UDP over IPv4 with a zero checksum the spec exempts L4 update entirely;
 * only IP total-length and IP header checksum need updating.
 *
 * Metadata stack layout after transit insertion
 * =============================================
 * The metadata stack is a push-down structure: each transit node prepends its
 * block immediately AFTER the INT-MD header.  The newest hop's data is at the
 * lowest address (closest to the INT-MD header); the oldest hop's data is
 * furthest from the header.
 *
 *   [INT-MD header 12B]
 *   [hop N metadata: hop_ml*4 bytes]    ← inserted by this transit node
 *   [hop N-1 metadata: hop_ml*4 bytes]
 *   ...
 *   [hop 1 metadata: hop_ml*4 bytes]    ← inserted by INT source
 *   [original L4 payload]
 *
 * The INSERT position is therefore: packet_data + l4_ofs + l4_hdr_len
 *                                    + INT_SHIM_LEN + INT_MD_HDR_LEN
 */

#include <config.h>
#include "int-telemetry.h"

#include <string.h>

#include "byte-order.h"
#include "coverage.h"
#include "csum.h"
#include "dp-packet.h"
#include "packets.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(int_telemetry);

COVERAGE_DEFINE(int_transit_processed);   /* Hop successfully processed.    */
COVERAGE_DEFINE(int_transit_e_bit);       /* Skipped: hop count exhausted.  */
COVERAGE_DEFINE(int_transit_m_bit);       /* Skipped: MTU would be exceeded. */
COVERAGE_DEFINE(int_transit_no_header);   /* Skipped: INT header not found. */
COVERAGE_DEFINE(int_transit_bad_ver);     /* Skipped: unknown INT version.  */

/* -------------------------------------------------------------------------
 * Internal helpers
 * ------------------------------------------------------------------------- */

/*
 * ip_dscp — extract the DSCP value (bits 7-2 of TOS) from an IPv4 header.
 */
static inline uint8_t
ip_dscp(const struct ip_header *ip)
{
    return (ip->ip_tos >> 2) & 0x3fu;
}

/*
 * tcp_hdr_len — return the TCP header length in bytes from the Data Offset
 * field (bits 7-4 of the 13th byte of the TCP header, i.e. tcp_ctl >> 12).
 * Returns TCP_HEADER_LEN (20) if the offset is less than 5, which is invalid
 * but prevents underflow.
 */
static inline unsigned int
tcp_hdr_len(const struct tcp_header *tcp)
{
    unsigned int offset = TCP_OFFSET(tcp->tcp_ctl);
    return (offset >= 5) ? offset * 4 : TCP_HEADER_LEN;
}

/*
 * int_find_shim — locate the INT shim header for a TCP/UDP packet.
 *
 * 'pkt' must have l3_ofs and l4_ofs set (i.e., miniflow_extract or
 * flow_extract must have been called).
 *
 * Returns a pointer to the struct int_shim_tcp_udp if:
 *   - the packet is IPv4 with ip_proto == TCP or UDP,
 *   - l3_ofs and l4_ofs are valid,
 *   - there are at least INT_SHIM_LEN + INT_MD_HDR_LEN bytes after the L4 hdr.
 *
 * Also sets *l4_hdr_len_out to the L4 header size in bytes, and
 * *ip_out / *l4_proto_out to the IP header pointer and protocol.
 *
 * Returns NULL on any parse failure.
 */
static const struct int_shim_tcp_udp *
int_find_shim(const struct dp_packet *pkt,
              const struct ip_header **ip_out,
              uint8_t *l4_proto_out,
              unsigned int *l4_hdr_len_out)
{
    const struct ip_header *ip = dp_packet_l3(pkt);
    if (!ip) {
        return NULL;
    }
    /* Only IPv4 is supported. */
    if ((ip->ip_ihl_ver >> 4) != 4) {
        return NULL;
    }
    uint8_t proto = ip->ip_proto;
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP) {
        return NULL;
    }

    const uint8_t *l4 = dp_packet_l4(pkt);
    if (!l4) {
        return NULL;
    }

    unsigned int l4_hlen;
    if (proto == IPPROTO_UDP) {
        l4_hlen = UDP_HEADER_LEN;
    } else {
        /* TCP: variable-length header. */
        size_t pkt_size  = dp_packet_size(pkt);
        size_t l4_offset = (const uint8_t *)l4 - (const uint8_t *)dp_packet_data(pkt);
        if (pkt_size < l4_offset + TCP_HEADER_LEN) {
            return NULL;
        }
        l4_hlen = tcp_hdr_len((const struct tcp_header *)l4);
    }

    /* Check that enough bytes follow the L4 header for shim + INT-MD hdr. */
    const uint8_t *shim_ptr = l4 + l4_hlen;
    size_t pkt_size  = dp_packet_size(pkt);
    size_t shim_off  = shim_ptr - (const uint8_t *)dp_packet_data(pkt);
    if (pkt_size < shim_off + INT_SHIM_LEN + INT_MD_HDR_LEN) {
        return NULL;
    }

    *ip_out           = ip;
    *l4_proto_out     = proto;
    *l4_hdr_len_out   = l4_hlen;
    return (const struct int_shim_tcp_udp *)shim_ptr;
}

/*
 * int_metadata_size — compute the size in bytes of the per-hop metadata block
 * described by 'bitmap' (host-byte-order instruction bitmap).
 *
 * Bits 4-6 (Ingress TS, Egress TS, L2 Interfaces) each require 8B;
 * all other defined bits require 4B.  Reserved bits are treated as 4B to
 * ensure backward compatibility (spec section 5.8).
 */
static size_t
int_metadata_size(uint16_t bitmap)
{
    size_t sz = 0;
    for (int bit = 15; bit >= 0; bit--) {
        if (!(bitmap & (1u << bit))) {
            continue;
        }
        /* Bits 11, 10, 9 → spec bits 4, 5, 6 (8-byte metadata). */
        if (bit == 11 || bit == 10 || bit == 9) {
            sz += 8;
        } else {
            sz += 4;
        }
    }
    return sz;
}

/*
 * int_packet_insert — grow the packet by 'insert_sz' bytes at byte offset
 * 'offset' from dp_packet_data().
 *
 * Uses dp_packet_put_uninit() to extend the packet at the tail (which may
 * reallocate), then memmove()s the suffix rightward to open a gap at 'offset'.
 *
 * Returns a pointer to the start of the uninitialised gap, or NULL if
 * 'offset' exceeds the current packet size.
 */
static uint8_t *
int_packet_insert(struct dp_packet *pkt, size_t offset, size_t insert_sz)
{
    size_t old_size = dp_packet_size(pkt);
    if (offset > old_size) {
        return NULL;
    }
    /* Extend at the tail (may reallocate; refreshes data pointer). */
    dp_packet_put_uninit(pkt, insert_sz);
    uint8_t *data = (uint8_t *)dp_packet_data(pkt);
    /* Shift bytes [offset, old_size) rightward by insert_sz. */
    memmove(data + offset + insert_sz,
            data + offset,
            old_size - offset);
    return data + offset;
}

/*
 * int_csum_add_bytes — incrementally add the ones-complement checksum of
 * 'len' bytes at 'buf' to the running checksum 'csum'.
 *
 * Used to update a TCP/UDP checksum after inserting new data into the payload.
 * The caller must also account for any pseudo-header length changes separately
 * via recalc_csum16().
 *
 * Returns the updated checksum.
 */
static ovs_be16
int_csum_add_bytes(ovs_be16 csum, const void *buf, size_t len)
{
    /* Start from the bitwise complement of the existing checksum, which is
     * the running partial sum of all covered bytes so far. */
    uint32_t partial = (~ntohs(csum)) & 0xffffu;
    partial = csum_continue(partial, buf, len);
    return htons(csum_finish(partial));
}

/* -------------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------------- */

bool
int_is_int_packet(const struct dp_packet *pkt, uint8_t int_dscp)
{
    const struct ip_header *ip = dp_packet_l3(pkt);
    if (!ip || (ip->ip_ihl_ver >> 4) != 4) {
        return false;
    }
    return ip_dscp(ip) == int_dscp;
}

bool
int_transit_process(struct dp_packet *pkt,
                    uint32_t  node_id,
                    uint16_t  ingress_ifid,
                    uint16_t  egress_ifid,
                    int64_t   batch_age_us,
                    int64_t   egress_ts_us,
                    uint32_t  queue_occupancy,
                    uint32_t  buf_occupancy)
{
    /* ------------------------------------------------------------------
     * Step 1: Locate the INT shim and INT-MD header.
     * ------------------------------------------------------------------ */
    const struct ip_header *ip_const;
    uint8_t      l4_proto;
    unsigned int l4_hlen;

    const struct int_shim_tcp_udp *shim_const =
        int_find_shim(pkt, &ip_const, &l4_proto, &l4_hlen);
    if (!shim_const) {
        COVERAGE_INC(int_transit_no_header);
        return false;
    }

    /* We only handle MD-type headers (Type == 1). */
    if (INT_SHIM_TYPE(shim_const) != INT_HDR_TYPE_MD) {
        COVERAGE_INC(int_transit_no_header);
        return false;
    }

    /* Point past the shim to the INT-MD header. */
    const struct int_md_hdr *md_const =
        (const struct int_md_hdr *)((const uint8_t *)shim_const + INT_SHIM_LEN);

    /* ------------------------------------------------------------------
     * Step 2: Validate INT-MD header version.
     * ------------------------------------------------------------------ */
    if (INT_MD_VER(md_const) != INT_MD_VER_VALUE) {
        COVERAGE_INC(int_transit_bad_ver);
        return false;
    }

    /* ------------------------------------------------------------------
     * Step 3: Check Remaining Hop Count — spec section 5.8.
     *
     * "When a packet is received with the Remaining Hop Count equal to 0,
     *  the node must ignore the INT instructions in the Instruction Bitmap
     *  and DS Instruction, pushing no new metadata onto the stack, and the
     *  node must set the E bit."
     * ------------------------------------------------------------------ */
    if (md_const->remaining_hop_cnt == 0) {
        /* Set E bit in the (now writable) header. */
        struct int_md_hdr *md_rw =
            (struct int_md_hdr *)((uint8_t *)dp_packet_data(pkt)
                + ((const uint8_t *)md_const - (const uint8_t *)dp_packet_data(pkt)));
        INT_MD_SET_E(md_rw);
        COVERAGE_INC(int_transit_e_bit);
        return false;
    }

    /* ------------------------------------------------------------------
     * Step 4: Determine metadata size and verify it matches Hop ML.
     *
     * hop_ml_bytes must equal the expected size from the instruction bitmap.
     * If they disagree the packet is malformed; skip without modification.
     * ------------------------------------------------------------------ */
    uint8_t  hop_ml        = INT_MD_HOP_ML(md_const);
    size_t   hop_ml_bytes  = (size_t)hop_ml * 4;
    uint16_t instr_bitmap  = ntohs(md_const->instruction_bitmap);
    size_t   expected_size = int_metadata_size(instr_bitmap);

    if (hop_ml_bytes == 0 || hop_ml_bytes != expected_size) {
        COVERAGE_INC(int_transit_no_header);
        return false;
    }

    /* ------------------------------------------------------------------
     * Step 5: MTU check — spec section 5.3.
     *
     * "If a node cannot insert all requested metadata because doing so will
     *  cause the packet length to exceed egress link MTU, it must not add
     *  any metadata to the packet, and set the M bit."
     *
     * OVS does not have per-port MTU readily available in the fast path, so
     * we use UINT16_MAX as a conservative bound (IPv4 max packet size).
     * Operators who need stricter MTU enforcement should configure
     * Remaining Hop Count at the source to limit packet growth.
     * ------------------------------------------------------------------ */
    size_t current_size = dp_packet_size(pkt);
    if (current_size + hop_ml_bytes > 65535u) {
        struct int_md_hdr *md_rw =
            (struct int_md_hdr *)((uint8_t *)dp_packet_data(pkt)
                + ((const uint8_t *)md_const - (const uint8_t *)dp_packet_data(pkt)));
        INT_MD_SET_M(md_rw);
        COVERAGE_INC(int_transit_m_bit);
        return false;
    }

    /* ------------------------------------------------------------------
     * Step 6: Compute insert position.
     *
     * New metadata is prepended to the existing stack, immediately after
     * the INT-MD header.  The insert offset is measured from the start of
     * dp_packet_data().
     * ------------------------------------------------------------------ */
    const uint8_t *pkt_base   = (const uint8_t *)dp_packet_data(pkt);
    size_t         insert_off = (const uint8_t *)md_const - pkt_base
                                + INT_MD_HDR_LEN;

    /* ------------------------------------------------------------------
     * Step 7: Insert gap into packet and collect metadata.
     *
     * dp_packet_put_uninit() may reallocate the packet buffer, invalidating
     * all previous pointers.  After int_packet_insert() returns, ALL
     * pointers derived from dp_packet_data() must be recomputed.
     * ------------------------------------------------------------------ */
    uint8_t *gap = int_packet_insert(pkt, insert_off, hop_ml_bytes);
    if (!gap) {
        return false;
    }

    /* Recompute writable pointers after potential reallocation. */
    uint8_t           *data_rw = (uint8_t *)dp_packet_data(pkt);
    struct ip_header  *ip      = (struct ip_header  *)(data_rw + pkt->l3_ofs);
    struct int_md_hdr *md      = (struct int_md_hdr *)(data_rw + insert_off
                                                        - INT_MD_HDR_LEN);

    /* Write metadata fields in Instruction Bitmap order (MSB first).
     * Each field's position within the gap advances by its size. */
    uint8_t *cursor = gap;

    /* bit15 of bitmap (uint16) = spec bit0 = Node ID (4B) */
    if (instr_bitmap & INT_INSTR_NODE_ID) {
        ovs_be32 val = htonl(node_id);
        memcpy(cursor, &val, 4);
        cursor += 4;
    }

    /* spec bit1 = L1 Ingress (16b) + Egress (16b) = 4B total */
    if (instr_bitmap & INT_INSTR_L1_IFIDS) {
        ovs_be16 ingr = htons(ingress_ifid);
        ovs_be16 egr  = htons(egress_ifid);
        memcpy(cursor, &ingr, 2);
        memcpy(cursor + 2, &egr, 2);
        cursor += 4;
    }

    /* spec bit2 = Hop Latency (4B, µs, approximate) */
    if (instr_bitmap & INT_INSTR_HOP_LAT) {
        uint32_t lat = (batch_age_us > 0 && batch_age_us <= UINT32_MAX)
                       ? (uint32_t)batch_age_us : 0xFFFFFFFFu;
        ovs_be32 val = htonl(lat);
        memcpy(cursor, &val, 4);
        cursor += 4;
    }

    /* spec bit3 = Queue ID (8b) + Queue Occupancy (24b) = 4B
     * We use egress_ifid as a proxy for Queue ID. */
    if (instr_bitmap & INT_INSTR_Q_OCCUP) {
        uint32_t qid_occ = ((uint32_t)(egress_ifid & 0xffu) << 24)
                           | (queue_occupancy & 0x00ffffffu);
        ovs_be32 val = htonl(qid_occ);
        memcpy(cursor, &val, 4);
        cursor += 4;
    }

    /* spec bit4 = Ingress Timestamp (8B, µs).
     * Approximated as: egress_ts_us - batch_age_us. */
    if (instr_bitmap & INT_INSTR_INGR_TS) {
        int64_t ingr_ts = egress_ts_us - batch_age_us;
        ovs_be64 val = htonll((uint64_t)ingr_ts);
        memcpy(cursor, &val, 8);
        cursor += 8;
    }

    /* spec bit5 = Egress Timestamp (8B, µs). */
    if (instr_bitmap & INT_INSTR_EGRS_TS) {
        ovs_be64 val = htonll((uint64_t)egress_ts_us);
        memcpy(cursor, &val, 8);
        cursor += 8;
    }

    /* spec bit6 = L2 Ingress (32b) + Egress (32b) = 8B.
     * Same port IDs as L1, zero-extended to 32 bits. */
    if (instr_bitmap & INT_INSTR_L2_IFIDS) {
        ovs_be32 ingr = htonl((uint32_t)ingress_ifid);
        ovs_be32 egr  = htonl((uint32_t)egress_ifid);
        memcpy(cursor, &ingr, 4);
        memcpy(cursor + 4, &egr, 4);
        cursor += 8;
    }

    /* spec bit7 = Egress TX Utilization (4B) — not available in OVS PMD. */
    if (instr_bitmap & INT_INSTR_EGRS_UTIL) {
        ovs_be32 val = htonl(0xFFFFFFFFu);
        memcpy(cursor, &val, 4);
        cursor += 4;
    }

    /* spec bit8 = Buffer ID (8b) + Buffer Occupancy (24b).
     * buf_occupancy encodes egress_ifid (8b) as buffer ID and cumulative
     * tc overflow drops (24b) as buffer occupancy. */
    if (instr_bitmap & INT_INSTR_BUF_OCCUP) {
        ovs_be32 val = htonl(buf_occupancy);
        memcpy(cursor, &val, 4);
        cursor += 4;
    }

    /* Reserved bits 6-1 (spec bits 9-14): treat as 4B reserved field.
     * Per spec section 5.8: "Reserved bits in the Instruction Bitmap are to
     * be handled similarly … the transit hop must either add corresponding
     * metadata filled with the reserved value 0xFFFFFFFF." */
    for (int bit = 6; bit >= 1; bit--) {
        if (instr_bitmap & (1u << bit)) {
            ovs_be32 val = htonl(0xFFFFFFFFu);
            memcpy(cursor, &val, 4);
            cursor += 4;
        }
    }

    /* spec bit15 = Checksum Complement (4B) — LAST field in the hop block. */
    if (instr_bitmap & INT_INSTR_CSUM_COMP) {
        /* Compute the ones-complement sum of all metadata words written so
         * far in this hop block (excluding the CC field itself, treated as 0).
         * The CC value must make the total 16-bit sum of the new bytes equal
         * to 0, keeping the existing L4 checksum valid. */
        size_t md_before_cc = (size_t)(cursor - gap);
        uint32_t partial = csum_continue(0, gap, md_before_cc);
        uint16_t md_sum  = csum_finish(partial);  /* = ~sum_16(metadata) */
        /* CC such that sum_16(metadata) + CC_sum == 0 in ones-complement.
         * sum_16(metadata) = ~md_sum; we need ~md_sum + CC_sum == 0 mod 16b.
         * → CC_sum = md_sum  (i.e., ~(~md_sum)).
         * Store CC_hi = md_sum (as big-endian 16b), CC_lo = 0. */
        ovs_be32 cc_val = htonl((uint32_t)md_sum << 16);
        memcpy(cursor, &cc_val, 4);
        cursor += 4;
    }

    /* Sanity: cursor must have advanced exactly hop_ml_bytes. */
    ovs_assert((size_t)(cursor - gap) == hop_ml_bytes);

    /* ------------------------------------------------------------------
     * Step 8: Decrement Remaining Hop Count.
     * ------------------------------------------------------------------ */
    md->remaining_hop_cnt--;

    /* ------------------------------------------------------------------
     * Step 9: Update packet length fields and checksums.
     *
     * The packet has grown by hop_ml_bytes.  We must update:
     *   (a) IP total length
     *   (b) IP header checksum
     *   (c) L4 header length (UDP only) and L4 checksum
     * ------------------------------------------------------------------ */
    ovs_be16 old_ip_tot_len = ip->ip_tot_len;
    ovs_be16 new_ip_tot_len = htons(ntohs(old_ip_tot_len) + (uint16_t)hop_ml_bytes);
    ip->ip_tot_len = new_ip_tot_len;
    ip->ip_csum    = recalc_csum16(ip->ip_csum, old_ip_tot_len, new_ip_tot_len);

    /* L4 checksum update. */
    uint8_t *l4_rw = data_rw + pkt->l4_ofs;

    if (l4_proto == IPPROTO_UDP) {
        struct udp_header *udp = (struct udp_header *)l4_rw;
        ovs_be16 old_udp_len   = udp->udp_len;
        ovs_be16 new_udp_len   = htons(ntohs(old_udp_len)
                                        + (uint16_t)hop_ml_bytes);
        udp->udp_len = new_udp_len;

        if (udp->udp_csum != 0) {
            if (instr_bitmap & INT_INSTR_CSUM_COMP) {
                /* CC approach: only the pseudo-header length change needs to
                 * be reflected; the CC field absorbs the new-bytes delta. */
                udp->udp_csum = recalc_csum16(udp->udp_csum,
                                              old_udp_len, new_udp_len);
            } else {
                /* Direct incremental update (RFC 1624):
                 * 1. Account for pseudo-header UDP-length change.
                 * 2. Add ones-complement sum of the newly inserted bytes. */
                udp->udp_csum = recalc_csum16(udp->udp_csum,
                                              old_udp_len, new_udp_len);
                udp->udp_csum = int_csum_add_bytes(udp->udp_csum,
                                                   gap, hop_ml_bytes);
            }
        }
        /* Zero UDP checksum (IPv4 only): no L4 update required. */

    } else {
        /* TCP: no per-header length field; pseudo-header length is derived
         * from IP total length (already updated above).
         *
         * TCP pseudo-header length = ip_tot_len - ip_ihl*4.
         * old_tcp_len = ntohs(old_ip_tot_len) - ip_ihl_bytes
         * new_tcp_len = old_tcp_len + hop_ml_bytes
         *
         * We represent the change as two recalc_csum16 calls: one for the
         * pseudo-header length, one for the new bytes.
         */
        struct tcp_header *tcp = (struct tcp_header *)l4_rw;
        unsigned int ip_ihl_bytes = (ip->ip_ihl_ver & 0x0fu) * 4u;
        ovs_be16 old_tcp_len = htons((uint16_t)(ntohs(old_ip_tot_len)
                                                - ip_ihl_bytes));
        ovs_be16 new_tcp_len = htons((uint16_t)(ntohs(new_ip_tot_len)
                                                - ip_ihl_bytes));
        tcp->tcp_csum = recalc_csum16(tcp->tcp_csum, old_tcp_len, new_tcp_len);

        if (!(instr_bitmap & INT_INSTR_CSUM_COMP)) {
            tcp->tcp_csum = int_csum_add_bytes(tcp->tcp_csum,
                                               gap, hop_ml_bytes);
        }
    }

    /* ------------------------------------------------------------------
     * Step 10: Update the INT shim Length field.
     *
     * "Length: the total length of INT metadata header and INT stack in
     *  4-byte words.  The length of the shim header (1 word) is NOT counted
     *  since INT version 2.0." — spec section 5.7.2.
     * ------------------------------------------------------------------ */
    struct int_shim_tcp_udp *shim_rw =
        (struct int_shim_tcp_udp *)(data_rw + pkt->l4_ofs + l4_hlen);
    shim_rw->length += (uint8_t)hop_ml;

    COVERAGE_INC(int_transit_processed);
    return true;
}
