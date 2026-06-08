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
 * AQM (Active Queue Management) — CoDel for the OVS userspace datapath.
 *
 * Implements CoDel (RFC 8289) adapted to OVS's PMD TX-batch model.
 *
 * Design notes
 * ============
 *
 * OVS PMD threads process packets in tight polling loops.  Outbound packets
 * are staged in a per-port output batch (struct tx_port.output_pkts) and
 * flushed to the NIC periodically or when the batch is full.  Under TX
 * backpressure the batch sits in memory longer than usual, which is the
 * congestion signal we measure as "sojourn time".
 *
 * Rather than per-packet sojourn timestamps (which would require a field in
 * every dp_packet), we timestamp the batch when its first packet arrives and
 * treat that age as the sojourn time at flush.  This is a conservative
 * approximation: the oldest packet has been waiting at least that long.
 *
 * ECN marking is preferred over dropping (RFC 3168 sect. 5.3):
 *   - ECT(0) / ECT(1) packets: CE bit set via IP_ECN_set_ce_safe().
 *   - Not-ECT packets: caller is asked to drop packet[0] (index 0).
 *
 * CoDel control law
 * =================
 *
 *   drop_next_{n+1} = drop_next_n + interval / sqrt(count)
 *
 * Starting with count = 1 this gives intervals of:
 *   interval, interval/√2, interval/√3, …
 * which gives an O(√rate) drop rate, matching TCP's AIMD convergence.
 */

#include <config.h>
#include "aqm.h"

#include <string.h>

#include "coverage.h"
#include "dp-packet.h"
#include "packets.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(aqm);

COVERAGE_DEFINE(aqm_ce_marked);      /* CE applied to ECN-capable packet. */
COVERAGE_DEFINE(aqm_drop_not_ect);   /* Packet dropped (Not-ECT, no CE). */
COVERAGE_DEFINE(aqm_codel_enter);    /* CoDel entered dropping state.     */

/* ---------------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------------ */

/*
 * Integer floor square root using two Newton–Raphson steps.
 * For x == 0 returns 0.  Result satisfies r*r <= x < (r+1)*(r+1).
 */
static uint32_t
isqrt32(uint32_t x)
{
    if (!x) {
        return 0;
    }
    /* Initial estimate: highest power-of-two <= sqrt(x). */
    uint32_t r = 1u << ((31 - __builtin_clz(x)) / 2);
    r = (r + x / r) >> 1;
    r = (r + x / r) >> 1;
    /* Correct downward if overshoot. */
    while (r * r > x) {
        r--;
    }
    return r;
}

/*
 * CoDel control law: schedule the next mark/drop time.
 *
 *   next = t + interval / sqrt(count)
 *
 * count >= 1 is guaranteed by the caller.
 */
static int64_t
codel_control_law(int64_t t, int64_t interval_us, uint32_t count)
{
    uint32_t sq = isqrt32(count);
    return t + (sq ? interval_us / (int64_t)sq : interval_us);
}

/*
 * Determine the IP version of a packet from its L3 header version nibble.
 * Returns true for IPv6, false for IPv4 (or unknown / no L3 header).
 */
static bool
pkt_is_ipv6(const struct dp_packet *pkt)
{
    const uint8_t *l3 = dp_packet_l3(pkt);
    return l3 && ((*l3 >> 4) == 6);
}

/*
 * Returns true if the packet carries a PolKA header (etherType 0x1234).
 *
 * For PolKA packets dp_packet_l3() points to the 20-byte routeId field,
 * not to an IP header.  The ECN helpers must not be called on these packets
 * because they would misinterpret the routeId bytes as IP header fields,
 * potentially corrupting the routeId or causing incorrect drop decisions.
 */
static bool
pkt_is_polka(const struct dp_packet *pkt)
{
    if (!dp_packet_is_eth(pkt)) {
        return false;
    }
    const struct eth_header *eth = dp_packet_data(pkt);
    return eth->eth_type == htons(ETH_TYPE_POLKA);
}

/* ---------------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------------ */

void
aqm_codel_init(struct aqm_codel_state *s,
               int64_t target_us, int64_t interval_us)
{
    memset(s, 0, sizeof *s);
    s->target_us   = target_us   ? target_us   : AQM_CODEL_TARGET_US;
    s->interval_us = interval_us ? interval_us : AQM_CODEL_INTERVAL_US;
}

/*
 * aqm_codel_run — apply CoDel to *batch* at time now_us.
 *
 * See aqm.h for the full contract.  Summary:
 *   returns -1  → no structural change (CE may or may not have been marked)
 *   returns  0  → caller must drop batch->packets[0] and compact arrays
 */
int
aqm_codel_run(struct aqm_codel_state *s,
              struct dp_packet_batch *batch,
              int64_t now_us)
{
    int64_t sojourn_us = now_us - s->batch_enqueue_us;

    /* ---------------------------------------------------------------
     * Phase 1: update the "above target" state.
     * ------------------------------------------------------------- */
    if (sojourn_us <= s->target_us) {
        /* Queue is healthy — reset and leave dropping state. */
        s->first_above_us = 0;
        s->dropping = false;
        return -1;
    }

    /* sojourn > target */
    if (s->first_above_us == 0) {
        /* First time above: start the grace interval. */
        s->first_above_us = now_us + s->interval_us;
        return -1;
    }

    if (now_us < s->first_above_us) {
        /* Still inside the grace window — wait. */
        return -1;
    }

    /* ---------------------------------------------------------------
     * Phase 2: we have been above target for a full interval.
     * Enter (or remain in) the dropping state and check the schedule.
     * ------------------------------------------------------------- */
    if (!s->dropping) {
        COVERAGE_INC(aqm_codel_enter);
        s->dropping = true;

        /* Fast re-convergence (RFC 8289 sect. 4.2): if we re-enter the
         * dropping state shortly after leaving it, inherit the previous
         * count so the marking rate ramps up faster. */
        if (s->count > 2
            && now_us - s->drop_next_us < 8 * s->interval_us) {
            s->count = s->lastcount;
        } else {
            s->count = 1;
        }
        s->lastcount   = s->count;
        s->drop_next_us = codel_control_law(now_us, s->interval_us, s->count);
    }

    /* Not yet time for the next mark/drop. */
    if (now_us < s->drop_next_us) {
        return -1;
    }

    /* ---------------------------------------------------------------
     * Phase 3: time to mark or drop.
     *
     * Prefer CE marking over dropping: scan for the first ECN-capable
     * packet.  If none is found, ask the caller to drop packet[0].
     * ------------------------------------------------------------- */
    struct dp_packet *pkt;
    DP_PACKET_BATCH_FOR_EACH (i, pkt, batch) {
        /* PolKA packets (etherType 0x1234) must be skipped: dp_packet_l3()
         * points to the routeId field, not to an IP header.  Calling the
         * ECN helpers on them would corrupt the routeId or produce a
         * spurious Not-ECT drop decision. */
        if (pkt_is_polka(pkt)) {
            continue;
        }
        bool is_v6 = pkt_is_ipv6(pkt);
        if (IP_ECN_set_ce_safe(pkt, is_v6)) {
            COVERAGE_INC(aqm_ce_marked);
            goto marked;
        }
    }

    /* No ECN-capable packet found — signal drop of packet[0]. */
    COVERAGE_INC(aqm_drop_not_ect);
    /* Advance schedule BEFORE returning so count reflects this drop. */
    s->count++;
    s->drop_next_us = codel_control_law(s->drop_next_us,
                                        s->interval_us, s->count);
    return 0;

marked:
    /* CE was applied; advance the CoDel schedule. */
    s->count++;
    s->drop_next_us = codel_control_law(s->drop_next_us,
                                        s->interval_us, s->count);
    return -1;
}
