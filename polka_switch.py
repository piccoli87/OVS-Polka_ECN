"""
polka_switch.py — Mininet helper for PolKA-enabled Open vSwitch.

Usage
-----
Instead of the generic OVSSwitch, use PolkaSwitch and pass nodeId:

    from polka_switch import PolkaSwitch

    net = Mininet(controller=None)
    s1 = net.addSwitch('s1', cls=PolkaSwitch, nodeId='0x8005')
    s2 = net.addSwitch('s2', cls=PolkaSwitch, nodeId='0x1021')

The nodeId is the 16-bit CRC polynomial that uniquely identifies this switch
node in the PolKA network.  Each node must have a distinct polynomial; the
network configurator chooses polynomials and routeIds such that:

    port = CRC16(routeId >> 16, nodeId) XOR (routeId & 0xFFFF)

yields a valid output port on each switch along the path.

Mapping to OVSDB
----------------
PolkaSwitch.start() calls:

    ovs-vsctl set Bridge <name> other_config:polka-node-id=<nodeId>

This triggers the PolKA forwarding logic in vswitchd (bridge.c reads the key
and passes the polynomial to the xlate layer via xlate_ofproto_set()).

Notes
-----
- Packets with etherType 0x1234 are forwarded by PolKA.
- All other traffic uses normal L2 learning (fail_mode=standalone).
- The nodeId can be decimal ("32773") or 0x-prefixed hex ("0x8005").
"""

from mininet.node import OVSSwitch


class PolkaSwitch(OVSSwitch):
    """OVSSwitch subclass with PolKA source-routing support.

    Parameters
    ----------
    name    : str   — switch name (e.g. 's1')
    nodeId  : str or int — the switch's CRC-16 polynomial (its "address" in
              the PolKA network).  Accepts decimal or 0x-prefixed hex strings,
              or a plain integer.  Defaults to 0 (PolKA disabled).
    **params: forwarded to OVSSwitch.__init__()
    """

    def __init__(self, name, nodeId=0, **params):
        self.nodeId = nodeId
        # PolKA uses standalone mode: normal L2 for non-PolKA traffic,
        # and the xlate layer intercepts etherType 0x1234 packets.
        params.setdefault('failMode', 'standalone')
        OVSSwitch.__init__(self, name, **params)

    def start(self, controllers):
        OVSSwitch.start(self, controllers)
        # Push the node polynomial into OVSDB so vswitchd picks it up.
        node_id_str = (hex(self.nodeId)
                       if isinstance(self.nodeId, int)
                       else str(self.nodeId))
        self.cmd(
            'ovs-vsctl set Bridge %s other_config:polka-node-id=%s'
            % (self.name, node_id_str)
        )
