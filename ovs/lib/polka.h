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

#ifndef POLKA_H
#define POLKA_H 1

/*
 * PolKA (Polynomial Key-based Architecture) — source routing core.
 *
 * PolKA encodes an entire network path into a single 160-bit routeId carried
 * in the packet header (etherType = 0x1234).  Each switch node applies a
 * CRC16 operation using its unique polynomial over the upper 144 bits of the
 * routeId, then XORs the result with the lower 16 bits to obtain the output
 * port number:
 *
 *   ndata  = routeId >> 16               (upper 18 bytes, 144 bits)
 *   dif    = routeId & 0xFFFF            (lower 2 bytes, 16 bits)
 *   port   = CRC16(ndata, node_poly) XOR dif
 *
 * This matches exactly the P4 implementation in polka-core.p4.
 *
 * The node polynomial is configured per-bridge via the OVSDB other_config key
 * "polka-node-id".  In Mininet, pass it as the nodeId keyword argument to the
 * PolkaSwitch class (see polka_switch.py), which maps it automatically:
 *
 *   sl = net.addSwitch('sl', cls=PolkaSwitch, nodeId='0x8005')
 *
 * Direct ovs-vsctl equivalent:
 *   ovs-vsctl set Bridge <name> other_config:polka-node-id=<hex_or_decimal>
 */

#include <stddef.h>
#include <stdint.h>

#define POLKA_ROUTE_ID_LEN 20   /* 160 bits = 20 bytes */

/*
 * polka_crc16 — compute a CRC-16 over 'data' of length 'len' bytes using
 * the given 16-bit generator polynomial.
 *
 * Each switch node uses a distinct polynomial as its network identifier.
 * The initial CRC value is 0x0000 (matches BMv2's crc16_custom default).
 */
uint16_t polka_crc16(const uint8_t *data, size_t len, uint16_t poly);

/*
 * polka_compute_nhop — compute the output port for this switch node.
 *
 * route_id : 20-byte (160-bit) routeId field extracted from the PolKA header.
 * node_poly: the CRC-16 generator polynomial of this node (its "address").
 *
 * Returns the 16-bit output port number.  The network configurator is
 * responsible for choosing polynomials and routeIds such that the returned
 * value is a valid port on this switch.
 */
uint16_t polka_compute_nhop(const uint8_t route_id[POLKA_ROUTE_ID_LEN],
                            uint16_t node_poly);

#endif /* POLKA_H */
