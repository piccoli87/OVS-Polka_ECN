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

#ifndef AQM_H
#define AQM_H 1

/*
 * AQM — Active Queue Management for the OVS userspace (dpif-netdev) datapath.
 *
 * Implements CoDel (Controlled Delay, RFC 8289) adapted to OVS's PMD
 * TX-batch model.  The "queue" is the per-port output_pkts batch that lives
 * in struct tx_port.  Sojourn time is measured as the age of the batch (time
 * from when the first packet entered an otherwise-empty batch to when the
 * batch is flushed to the NIC).
 *
 * When the CoDel algorithm decides to mark or drop:
 *   - ECN-capable packets (ECT(0) or ECT(1)) receive a CE mark via
 *     IP_ECN_set_ce_safe() — no packet is removed from the batch.
 *   - Not-ECT packets cannot carry a CE mark; aqm_codel_run() returns the
 *     index of the packet to drop, and the caller is responsible for removing
 *     it from the batch (and any parallel rxqs-tracking array).
 *
 * Each struct aqm_codel_state is owned by exactly one PMD thread (via
 * struct tx_port), so no locking is required.
 */

#include <stdbool.h>
#include <stdint.h>

struct dp_packet_batch;

/* CoDel defaults (RFC 8289, sect. 4.2). */
#define AQM_CODEL_TARGET_US    5000LL    /* 5 ms sojourn target   */
#define AQM_CODEL_INTERVAL_US  100000LL  /* 100 ms marking window */

/*
 * Per-TX-port CoDel state.
 *
 * Fields are written and read only by the PMD thread that owns the associated
 * struct tx_port — no synchronisation is needed.
 */
struct aqm_codel_state {
    /* --- Parameters (set at init, constant afterwards) --- */
    int64_t target_us;       /* Sojourn target (µs). */
    int64_t interval_us;     /* Measurement / marking interval (µs). */

    /* --- Sliding-window minimum-sojourn state --- */
    int64_t first_above_us;  /* Epoch when sojourn first exceeded target.
                              * 0 means "not yet above target". */

    /* --- Dropping / marking state --- */
    bool    dropping;        /* True while CoDel is in the dropping state. */
    int64_t drop_next_us;    /* Scheduled time of the next mark or drop. */
    uint32_t count;          /* Marks/drops issued in the current epoch. */
    uint32_t lastcount;      /* count at the start of the current epoch
                              * (used to accelerate re-convergence). */

    /* --- Batch timestamp --- */
    /* Set by the caller when the first packet enters an empty output batch;
     * used as the sojourn start time when the batch is flushed. */
    int64_t batch_enqueue_us;
};

/*
 * aqm_codel_init — initialise CoDel state.
 *
 * Pass 0 for target_us and/or interval_us to use the RFC 8289 defaults
 * (AQM_CODEL_TARGET_US and AQM_CODEL_INTERVAL_US respectively).
 */
void aqm_codel_init(struct aqm_codel_state *s,
                    int64_t target_us, int64_t interval_us);

/*
 * aqm_codel_run — apply CoDel to the TX batch at time now_us (µs).
 *
 * The function examines the batch age (now_us - s->batch_enqueue_us) and
 * updates the CoDel state machine.  When marking is triggered it scans the
 * batch for the first ECN-capable packet, applies CE in-place, and returns -1
 * (no packet needs to be removed).  If no ECN-capable packet is found, it
 * returns 0 — the caller MUST delete batch->packets[0] and compact both the
 * batch and any parallel per-packet arrays (e.g. output_pkts_rxqs).
 *
 * Returns -1 when no structural change to the batch is required.
 * Returns  0 when batch->packets[0] must be dropped by the caller.
 */
int aqm_codel_run(struct aqm_codel_state *s,
                  struct dp_packet_batch *batch,
                  int64_t now_us);

#endif /* AQM_H */
