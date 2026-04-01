#!/usr/bin/env python3
"""
topology.py — ARP Flood Detection — Fixed Version
==================================================
Architecture:
    s11 (core)
    / | \ \ \
  s12 s13 s14 s15 s16 (aggregation)
   /\   /\   /\   /\   /\
 s1 s2 s3 s4 s5 s6 s7 s8 s9 s10 (edge)
 8h  8h  8h  8h  8h  8h  8h  8h  8h  8h

MAC scheme (FIXED):
    Host on edge switch sN, port j → MAC = 00:00:00:00:0N:0j
    Example: h1 on s1 port1 → 00:00:00:00:01:01
    This matches BMv2's expectation for unique MACs
"""

import os, sys, time, subprocess
from mininet.net   import Mininet
from mininet.node  import Host, Switch
from mininet.link  import TCLink
from mininet.cli   import CLI
from mininet.log   import setLogLevel, info, error
from mininet.clean import cleanup

BASE   = "/opt/p4work/arp_flood_detection"
P4JSON = os.path.join(BASE, "build/arp_monitor.json")
LOGDIR = "/tmp/bmv2_logs"
CFGDIR = os.path.join(BASE, "switch_config")
os.makedirs(LOGDIR, exist_ok=True)
os.makedirs(CFGDIR, exist_ok=True)

HOSTS_PER_EDGE = 8

# Tree structure: edge → aggregation
EDGE_TO_AGG = {
    1: 12, 2: 12,   # s1,s2 → s12
    3: 13, 4: 13,   # s3,s4 → s13
    5: 14, 6: 14,   # s5,s6 → s14
    7: 15, 8: 15,   # s7,s8 → s15
    9: 16, 10: 16,  # s9,s10 → s16
}
AGG_TO_ROOT = {12: 11, 13: 11, 14: 11, 15: 11, 16: 11}
ROOT = 11


def compute_mac_tables():
    """
    Compute MAC→port for every switch with CORRECT MAC format.
    MAC = 00:00:00:00:0N:0j where:
        N = switch number (1-10 for edge, 11 for root, 12-16 for agg)
        j = port number (1-8 for hosts)
    """
    # Build host MAC list per edge switch
    # sw_hosts[sw_num] = [(mac, local_port), ...]
    sw_hosts = {}
    for sw_num in range(1, 11):  # edge switches 1-10
        sw_hosts[sw_num] = []
        for j in range(1, HOSTS_PER_EDGE + 1):
            # FIXED: Use consistent MAC format
            mac = f"00:00:00:00:{sw_num:02x}:{j:02x}"
            sw_hosts[sw_num].append((mac, j))  # port = j (1-indexed)
            info(f"    Host s{sw_num}p{j} MAC {mac}\n")

    # Aggregation switches have no hosts
    for sw_num in [11, 12, 13, 14, 15, 16]:
        sw_hosts[sw_num] = []

    tables = {}

    # ── Edge switches (s1-s10) ─────────────────────────────────────────
    for sw_num in range(1, 11):
        tables[sw_num] = {}
        # FIXED: Use 0-indexed ports for BMv2
        uplink_port = HOSTS_PER_EDGE  # port 8 (0-indexed) - was 9

        # Local hosts → direct port (convert to 0-indexed)
        for mac, port in sw_hosts[sw_num]:
            tables[sw_num][mac] = port - 1  # Convert 1-indexed to 0-indexed

        # All remote hosts → uplink port (0-indexed)
        for other_sw in range(1, 11):
            if other_sw == sw_num:
                continue
            for mac, _ in sw_hosts[other_sw]:
                tables[sw_num][mac] = uplink_port

        # Add MACs for aggregation and core switches? No - they're not hosts
        # Traffic to switches themselves goes through uplink too

    # ── Aggregation switches (s12-s16) ─────────────────────────────────
    agg_edges = {}  # agg_sw → [edge1, edge2]
    for edge, agg in sorted(EDGE_TO_AGG.items()):
        agg_edges.setdefault(agg, []).append(edge)

    for agg_sw, edges in agg_edges.items():
        tables[agg_sw] = {}
        # FIXED: Use 0-indexed ports
        root_port = len(edges)  # port 2 (0-indexed) - was 3

        # MACs from edge1 → port 0, edge2 → port 1 (0-indexed)
        for port_idx, edge_sw in enumerate(edges, start=0):  # start at 0
            for mac, _ in sw_hosts[edge_sw]:
                tables[agg_sw][mac] = port_idx

        # All other MACs (from other edges) → root uplink (port 2)
        all_edges = set(range(1, 11))
        local_edges = set(edges)
        remote_edges = all_edges - local_edges
        
        for edge_sw in remote_edges:
            for mac, _ in sw_hosts[edge_sw]:
                tables[agg_sw][mac] = root_port

    # ── Core switch (s11) ──────────────────────────────────────────────
    agg_order = [12, 13, 14, 15, 16]
    tables[ROOT] = {}
    # FIXED: Use 0-indexed ports
    for port_idx, agg_sw in enumerate(agg_order, start=0):  # start at 0
        # All hosts under this aggregation switch
        edges = agg_edges[agg_sw]
        for edge_sw in edges:
            for mac, _ in sw_hosts[edge_sw]:
                tables[ROOT][mac] = port_idx

    return tables, sw_hosts


class P4Switch(Switch):
    def __init__(self, name, sw_id, json_path=P4JSON, **kwargs):
        kwargs.setdefault('failMode', 'standalone')
        super().__init__(name, **kwargs)
        self.sw_id       = sw_id
        self.json_path   = json_path
        self.thrift_port = 9090 + (sw_id - 1) * 10  # Avoid port conflicts
        self.log_file    = os.path.join(LOGDIR, f"{name}.log")
        self.proc        = None
        self.cpu_intf    = f"{name}-cpu0"
        self.cpu_ctrl    = f"{name}-cpu1"

    def _create_cpu_veth(self):
        os.system(f"ip link del {self.cpu_intf} 2>/dev/null || true")
        os.system(f"ip link add {self.cpu_intf} type veth peer name {self.cpu_ctrl}")
        os.system(f"ip link set {self.cpu_intf} up")
        os.system(f"ip link set {self.cpu_ctrl} up")
        info(f"  [{self.name}] CPU veth: {self.cpu_intf} ↔ {self.cpu_ctrl}\n")

    def start(self, controllers):
        self._create_cpu_veth()
        iface_args = []
        # IMPORTANT: BMv2 ports are 0-indexed in interface list
        port_idx = 0
        for intf in self.intfList():
            if intf.name == "lo":
                continue
            iface_args += ["-i", f"{port_idx}@{intf.name}"]
            info(f"    {self.name}: port {port_idx} = {intf.name}\n")
            port_idx += 1
        # CPU port always 255
        iface_args += ["-i", f"255@{self.cpu_intf}"]

        cmd = [
            "simple_switch",
            "--device-id",   str(self.sw_id),
            "--thrift-port", str(self.thrift_port),
            "--log-file",    self.log_file,
            "--log-flush",
            "--log-level",   "warn",
        ] + iface_args + [self.json_path]

        info(f"  [{self.name}] id={self.sw_id} thrift={self.thrift_port} "
             f"ports={port_idx} cpu={self.cpu_intf}\n")

        with open(self.log_file, "w") as lf:
            self.proc = subprocess.Popen(cmd, stdout=lf, stderr=lf,
                                        close_fds=True)

    def stop(self, deleteIntfs=True):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:    self.proc.wait(timeout=3)
            except: self.proc.kill()
        os.system(f"ip link del {self.cpu_intf} 2>/dev/null || true")
        super().stop(deleteIntfs)

    def configure(self, mac_table, switch_type):
        """
        Configure switch with runtime commands.
        switch_type: 'edge', 'agg', or 'core'
        """
        # Get all BMv2 ports (excluding CPU port 255)
        ports = []
        for idx, intf in enumerate(self.intfList()):
            if intf.name != "lo":
                ports.append(idx)
        
        # BMv2 uses 0-indexed ports everywhere
        all_ports = ports  # Already 0-indexed
        
        lines = []
        lines.append(f"table_add tbl_switch_id set_switch_id => {self.sw_id}")
        lines.append("mirroring_add 100 255")
        lines.append("mc_mgrp_create 1")

        # Flood group should include ALL PORTS EXCEPT CPU (0-indexed)
        flood_ports = all_ports

        # Create multicast nodes for each port
        for handle, port in enumerate(flood_ports):
            lines.append(f"mc_node_create {handle} {port}")
        
        # Associate all nodes with multicast group 1
        for handle in range(len(flood_ports)):
            lines.append(f"mc_node_associate 1 {handle}")

        # Add MAC table entries (all 80 hosts) - ports are already 0-indexed
        added = 0
        for mac, port in sorted(mac_table.items()):
            lines.append(f"table_add tbl_l2 l2_forward {mac} => {port}")
            added += 1
            if added <= 3:  # Show first few for debugging
                info(f"    {self.name}: {mac} → port {port}\n")

        cfg_path = os.path.join(CFGDIR, f"{self.name}_runtime.txt")
        with open(cfg_path, "w") as f:
            f.write("\n".join(lines) + "\n")

        # Apply configuration
        cmd = f"simple_switch_CLI --thrift-port {self.thrift_port} < {cfg_path}"
        result = subprocess.run(cmd, shell=True, capture_output=True, 
                               text=True, timeout=30)
        
        errs = [l for l in result.stdout.splitlines()
                if "error" in l.lower() and "duplicate" not in l.lower()]
        if errs:
            error(f"  [{self.name}] CLI errors: {errs[:2]}\n")
        else:
            info(f"  [{self.name}] ✓ configured ({switch_type}) "
                 f"flood_ports={flood_ports}, mac_entries={added}\n")


def build_network():
    net = Mininet(
        controller=None, switch=P4Switch, host=Host,
        link=TCLink, autoSetMacs=False,  # We set MACs manually
        autoStaticArp=False, build=False,
    )

    info("\n[TOPO] Adding switches...\n")
    switches = {}
    # All 20 switches
    for sw_num in list(range(1, 11)) + [11, 12, 13, 14, 15, 16]:
        sw = net.addSwitch(f"s{sw_num}", cls=P4Switch,
                          sw_id=sw_num, json_path=P4JSON)
        switches[f"s{sw_num}"] = sw

    info("[TOPO] Adding 80 hosts (8 per edge switch)...\n")
    host_idx = 1
    for sw_num in range(1, 11):
        for j in range(1, HOSTS_PER_EDGE + 1):
            # FIXED: Use correct MAC format
            mac = f"00:00:00:00:{sw_num:02x}:{j:02x}"
            ip  = f"10.{sw_num}.{j}.1/16"  # Changed IP scheme
            h   = net.addHost(f"h{host_idx}", ip=ip, mac=mac)
            net.addLink(h, switches[f"s{sw_num}"])
            host_idx += 1

    info("[TOPO] Adding edge→aggregation uplinks...\n")
    for edge, agg in sorted(EDGE_TO_AGG.items()):
        net.addLink(switches[f"s{edge}"], switches[f"s{agg}"])
        info(f"  s{edge} (port {HOSTS_PER_EDGE}) → s{agg}\n")  # 0-indexed

    info("[TOPO] Adding aggregation→root uplinks...\n")
    for agg in sorted(AGG_TO_ROOT.keys()):
        net.addLink(switches[f"s{agg}"], switches[f"s{ROOT}"])
        info(f"  s{agg} → s{ROOT}\n")

    return net, switches


def main():
    setLogLevel("info")
    cleanup()

    if not os.path.exists(P4JSON):
        error(f"\n[!] {P4JSON} not found.\n")
        sys.exit(1)

    info("\n" + "="*60)
    info("\n[TOPO] Tree topology: s11(root) → s12-s16(agg) → s1-s10(edge) → 80 hosts\n")
    info("="*60 + "\n")

    info("[TOPO] Computing MAC tables with CORRECT format...\n")
    mac_tables, sw_hosts = compute_mac_tables()

    info("\n[TOPO] Building network...\n")
    net, switches = build_network()

    info("\n[TOPO] Starting network...\n")
    net.start()

    info("\n[TOPO] Waiting for Thrift ports to bind...\n")
    time.sleep(5)

    info("\n[TOPO] Configuring switches...\n")
    for name in sorted(switches, key=lambda x: int(x[1:])):
        sw_num = int(name[1:])
        if sw_num <= 10:
            switch_type = "edge"
        elif sw_num == 11:
            switch_type = "core"
        else:
            switch_type = "aggregation"
        switches[name].configure(mac_tables[sw_num], switch_type)

    # Generate controller command
    ifaces = " ".join(
        switches[f"s{i}"].cpu_ctrl
        for i in list(range(1, 11)) + [11, 12, 13, 14, 15, 16]
    )
    
    info("\n" + "="*60)
    info("\n[TOPO] NETWORK READY\n")
    info("="*60)
    info("\nTo start controller:\n")
    info(f"  sudo python3 {BASE}/controller/controller.py \\\n")
    info(f"    --interfaces {ifaces} --label normal\n")
    info("\nConnectivity tests:\n")
    info("  Same switch:    h1 ping -c 3 10.1.2.1\n")  # Fixed: h2 is 10.1.2.1
    info("  Different edge: h1 ping -c 3 10.2.1.1\n")
    info("  Cross-agg:      h1 ping -c 3 10.3.1.1\n")
    info("  Cross-core:     h1 ping -c 3 10.5.1.1\n")
    info("="*60 + "\n")

    CLI(net)
    net.stop()


if __name__ == "__main__":
    main()
