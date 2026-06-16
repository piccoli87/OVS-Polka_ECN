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

#ifndef INT_TELEMETRY_H
#define INT_TELEMETRY_H 1

/*
 * INT (In-band Network Telemetry) — transit node processing.
 *
 * Implements the INT-MD (eMbed Data) transit hop behaviour as specified in
 * "In-band Network Telemetry (INT) Dataplane Specification v2.1"
 * (P4.org Applications Working Group, 2020-11-11).
 *
 * An INT-MD transit node must, for each matching packet:
 *
 *   1. Detect the INT header (via DSCP marker in the IPv4 TOS field).
 *   2. Parse the 4-byte INT shim header (TCP/UDP encapsulation).
 *   3. Parse the 12-byte INT-MD metadata header.
 *   4. Check Remaining Hop Count — if zero, set E-bit and skip.
 *   5. Check MTU — if inserting would exceed egress MTU, set M-bit and skip.
 *   6. Collect metadata as instructed by the Instruction Bitmap.
 *   7. Prepend the hop's metadata block immediately after the INT-MD header
 *      (stack grows toward the source: newest hop at the top).
 *   8. Decrement Remaining Hop Count.
 *   9. Update IP total length, IP checksum, and L4 checksum.
 *
 * Only INT-MD over TCP/UDP (section 5.7.2 of the spec) with DSCP-based
 * detection (option 2) is supported.  The DSCP value INT_DSCP (0x17)
 * matches the value used in the spec examples.
 *
 * Configuration via OVSDB other_config keys (on the Open_vSwitch table):
 *
 *   int-node-id    — 32-bit node identifier, unique within the INT domain.
 *                    0 disables INT transit processing (default).
 *   int-dscp       — DSCP value that marks INT packets (default 0x17).
 *
 * Example:
 *   ovs-vsctl set Open_vSwitch . \
 *       other_config:int-node-id=42 \
 *       other_config:int-dscp=0x17
 */

#include <stdbool.h>
#include <stdint.h>

#include "openvswitch/types.h"
#include "util.h"

struct dp_packet;

/* -------------------------------------------------------------------------
 * INT DSCP marker (IPv4 TOS field, bits 7-2).
 *
 * 0x17 = binary 010111 — the value used in all INT spec v2.1 examples.
 * Operators may configure a different value via other_config:int-dscp.
 * ------------------------------------------------------------------------- */
#define INT_DSCP_DEFAULT  0x17u   /* decimal 23, matches spec examples */

/* -------------------------------------------------------------------------
 * INT Header Types (carried in the shim's Type field, bits 7-4).
 * ------------------------------------------------------------------------- */
#define INT_HDR_TYPE_MD   1u   /* MD-type: embed instructions + metadata */
#define INT_HDR_TYPE_DEST 2u   /* Destination-type: consumed by Sink only */
#define INT_HDR_TYPE_MX   3u   /* MX-type: embed instructions only        */

/* -------------------------------------------------------------------------
 * INT Shim Header for TCP/UDP encapsulation (4 bytes).
 *
 * Placed immediately after the L4 (TCP or UDP) header, before the INT-MD
 * metadata header and the metadata stack.
 *
 * Bit layout (network byte order):
 *
 *   Byte 0: [7:4] Type  [3:2] NPT  [1:0] Reserved
 *   Byte 1: Length (INT-MD header + metadata stack in 4-byte words;
 *           the shim itself is NOT counted since INT spec v2.0)
 *   Bytes 2-3: UDP port, IP proto, or DSCP (depends on NPT)
 *     NPT=0: [15:8] reserved, [13:8] original DSCP (bits 5-0 of byte 2)
 *     NPT=1: original UDP destination port
 *     NPT=2: [7:0] original IP protocol (byte 3)
 *
 * NPT values:
 *   0 — original packet was NOT a UDP packet needing port restoration
 *   1 — UDP payload follows INT stack; last 2 bytes = original UDP dst port
 *   2 — another L4 header follows INT stack; byte 3 = original IP proto
 * ------------------------------------------------------------------------- */
#define INT_SHIM_LEN  4u

OVS_PACKED(
struct int_shim_tcp_udp {
    uint8_t  type_npt;    /* [7:4]=Type, [3:2]=NPT, [1:0]=Reserved */
    uint8_t  length;      /* MD header + metadata stack in 4B words */
    ovs_be16 proto_info;  /* NPT-dependent: UDP port / DSCP / IP proto */
});
BUILD_ASSERT_DECL(sizeof(struct int_shim_tcp_udp) == INT_SHIM_LEN);

#define INT_SHIM_TYPE(s)    (((s)->type_npt >> 4) & 0x0fu)
#define INT_SHIM_NPT(s)     (((s)->type_npt >> 2) & 0x03u)

/* -------------------------------------------------------------------------
 * INT-MD Metadata Header (12 bytes).
 *
 * Follows immediately after the INT shim header.  The metadata stack grows
 * after this fixed 12-byte header: each transit hop prepends its block.
 *
 * First word (32 bits), network byte order:
 *   bits 31-28: Ver  (4b)  — must be 2 for this spec version
 *   bit  27:    D    (1b)  — Discard: sink must discard packet after extract
 *   bit  26:    E    (1b)  — Max Hop Count exceeded (set by transit, not src)
 *   bit  25:    M    (1b)  — MTU exceeded at some hop
 *   bits 24-13: Reserved (12b)
 *   bits 12-8:  Hop ML (5b) — per-hop metadata length in 4-byte words
 *   bits  7-0:  Remaining Hop Count (8b)
 *
 * Second word: Instruction Bitmap (16b) | Domain Specific ID (16b)
 * Third word:  DS Instruction (16b)     | DS Flags (16b)
 * ------------------------------------------------------------------------- */
#define INT_MD_HDR_LEN   12u
#define INT_MD_VER_VALUE  2u   /* version field must be 2 */

OVS_PACKED(
struct int_md_hdr {
    /* Word 0 */
    uint8_t  ver_d_e_m;         /* [7:4]=Ver, [3]=D, [2]=E, [1]=M, [0]=Rsv */
    uint8_t  reserved;          /* bits 23-16: reserved */
    uint8_t  rsv_hop_ml;        /* [7:5]=reserved, [4:0]=Hop ML (5 bits) */
    uint8_t  remaining_hop_cnt; /* bits 7-0 */
    /* Word 1 */
    ovs_be16 instruction_bitmap;
    ovs_be16 domain_specific_id;
    /* Word 2 */
    ovs_be16 ds_instruction;
    ovs_be16 ds_flags;
});
BUILD_ASSERT_DECL(sizeof(struct int_md_hdr) == INT_MD_HDR_LEN);

/* Field access macros for int_md_hdr. */
#define INT_MD_VER(h)           (((h)->ver_d_e_m >> 4) & 0x0fu)
#define INT_MD_D_BIT(h)         (((h)->ver_d_e_m >> 3) & 0x01u)
#define INT_MD_E_BIT(h)         (((h)->ver_d_e_m >> 2) & 0x01u)
#define INT_MD_M_BIT(h)         (((h)->ver_d_e_m >> 1) & 0x01u)
#define INT_MD_HOP_ML(h)        ((h)->rsv_hop_ml & 0x1fu)

/* Setters for E and M flag bits in ver_d_e_m. */
#define INT_MD_SET_E(h)         ((h)->ver_d_e_m |= 0x04u)
#define INT_MD_SET_M(h)         ((h)->ver_d_e_m |= 0x02u)

/* -------------------------------------------------------------------------
 * Instruction Bitmap bit definitions.
 *
 * The 16-bit Instruction Bitmap is stored big-endian.  "bit0 (MSB)" in the
 * spec corresponds to bit 15 of the uint16_t after ntohs().
 *
 * Metadata sizes (per hop block, packed in order of bit position):
 *   4B fields: Node ID, L1 Interfaces, Hop Latency, Queue Occ,
 *              Egress Util, Buffer Occ, Checksum Complement
 *   8B fields: Ingress Timestamp, Egress Timestamp, L2 Interfaces
 * ------------------------------------------------------------------------- */
#define INT_INSTR_NODE_ID    (1u << 15)  /* spec bit0  — Node ID (4B)            */
#define INT_INSTR_L1_IFIDS   (1u << 14)  /* spec bit1  — L1 Ingress+Egress (4B)  */
#define INT_INSTR_HOP_LAT    (1u << 13)  /* spec bit2  — Hop Latency (4B)        */
#define INT_INSTR_Q_OCCUP    (1u << 12)  /* spec bit3  — Queue ID + Occ (4B)     */
#define INT_INSTR_INGR_TS    (1u << 11)  /* spec bit4  — Ingress Timestamp (8B)  */
#define INT_INSTR_EGRS_TS    (1u << 10)  /* spec bit5  — Egress Timestamp (8B)   */
#define INT_INSTR_L2_IFIDS   (1u <<  9)  /* spec bit6  — L2 Ingress+Egress (8B)  */
#define INT_INSTR_EGRS_UTIL  (1u <<  8)  /* spec bit7  — Egress TX Util (4B)     */
#define INT_INSTR_BUF_OCCUP  (1u <<  7)  /* spec bit8  — Buffer ID + Occ (4B)    */
/* bits 6-1 (spec bits 9-14): reserved in this version */
#define INT_INSTR_CSUM_COMP  (1u <<  0)  /* spec bit15 — Checksum Complement (4B)*/

/* Checksum Complement reserved value (indicates CC was NOT computed). */
#define INT_CSUM_COMP_INVALID  0xFFFFFFFFu

/* -------------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------------- */

/*
 * int_is_int_packet — returns true if the packet carries an INT header.
 *
 * Detection is DSCP-based: the IPv4 TOS field's DSCP bits (bits 7-2) must
 * match 'int_dscp'.  Only IPv4 is supported.  Non-IP packets and IPv6
 * packets always return false.
 */
bool int_is_int_packet(const struct dp_packet *pkt, uint8_t int_dscp);

/*
 * int_transit_process — apply INT-MD transit hop processing to one packet.
 *
 * Performs steps 2–9 of the transit node algorithm (see module header).
 * The packet is modified in place:
 *   - hop_ml * 4 bytes are inserted immediately after the INT-MD header,
 *   - IP total length, IP checksum, and L4 checksum are updated.
 *
 * Parameters:
 *   pkt             — the packet to process (modified in place)
 *   node_id         — this node's INT domain identifier (from config)
 *   ingress_ifid    — 16-bit ingress interface identifier
 *   egress_ifid     — 16-bit egress interface identifier
 *   batch_age_us    — approximate hop latency in microseconds
 *                     (may use TX-batch age as a conservative estimate)
 *   egress_ts_us    — egress timestamp in microseconds (monotonic clock)
 *   queue_occupancy — queue occupancy in packets (from tc qdisc backlog)
 *   buf_occupancy  — buffer occupancy proxy: cumulative tc overflow drops,
 *                    encoded as buf_id(8b)=egress_ifid | drops(24b)
 *
 * Returns true if the packet was modified, false if it was skipped
 * (E-bit set, M-bit set, unsupported header, or not an INT-MD packet).
 */
bool int_transit_process(struct dp_packet *pkt,
                         uint32_t node_id,
                         uint16_t ingress_ifid,
                         uint16_t egress_ifid,
                         int64_t  batch_age_us,
                         int64_t  egress_ts_us,
                         uint32_t queue_occupancy,
                         uint32_t buf_occupancy);

#endif /* INT_TELEMETRY_H */
