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
 * PolKA next-hop computation.
 *
 * Implements the forwarding algorithm from polka-core.p4:
 *
 *   action srcRoute_nhop() {
 *       bit<160> ndata = routeid >> 16;
 *       bit<16>  dif   = (bit<16>)(routeid ^ (ndata << 16));
 *       hash(nresult, HashAlgorithm.crc16_custom, 0, {ndata}, ...);
 *       nport = nresult ^ dif;
 *   }
 *
 * The CRC-16 algorithm uses a standard bit-by-bit implementation with a
 * configurable polynomial, matching BMv2's crc16_custom behaviour:
 *   - initial value : 0x0000
 *   - final XOR     : 0x0000
 *   - reflect input : false
 *   - reflect output: false
 */

#include <config.h>
#include "polka.h"

#include <string.h>

/*
 * CRC-16 with configurable polynomial.
 *
 * Processes each byte MSB-first.  The polynomial is provided in normal
 * (non-reflected) form — e.g., 0x8005 for CRC-16/IBM.
 */
uint16_t
polka_crc16(const uint8_t *data, size_t len, uint16_t poly)
{
    uint16_t crc = 0x0000;

    for (size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)data[i] << 8;
        for (int bit = 0; bit < 8; bit++) {
            if (crc & 0x8000u) {
                crc = (uint16_t)((crc << 1) ^ poly);
            } else {
                crc = (uint16_t)(crc << 1);
            }
        }
    }
    return crc;
}

/*
 * polka_compute_nhop — PolKA forwarding decision.
 *
 * routeId layout (big-endian, 20 bytes = 160 bits):
 *
 *   byte  0 ─ 17  : ndata  (upper 144 bits)  → input to CRC-16
 *   byte 18 ─ 19  : dif    (lower  16 bits)  → XOR'd with CRC result
 *
 *   port = CRC16(ndata, node_poly) XOR dif
 */
uint16_t
polka_compute_nhop(const uint8_t route_id[POLKA_ROUTE_ID_LEN],
                   uint16_t node_poly)
{
    /* ndata = route_id[0..17] (routeId >> 16 in the P4 code). */
    uint16_t nresult = polka_crc16(route_id, 18, node_poly);

    /* dif = route_id[18..19] interpreted as a big-endian uint16. */
    uint16_t dif = ((uint16_t)route_id[18] << 8) | route_id[19];

    return nresult ^ dif;
}
