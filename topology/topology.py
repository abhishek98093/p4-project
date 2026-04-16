#!/usr/bin/env python3
r"""
topology_simple_fixed.py — Reduced ARP Flood Detection Topology
================================================================
Architecture:
      s11 (core)
      /    \
    s1      s2 (edge)
   / \     / \
  h1-h8   h9-h16

MAC scheme (identical to original):
    Host on edge switch sN, port j → MAC = 00:00:00:00:0N:0j
    Example: h1 on s1 port1 → 00:00:00:00:01:01
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
ROOT = 11
EDGE_SWITCHES = [1, 2]
ALL_SWITCH_NUMS = [1, 2, 11]

def compute_mac_tables():
    """
    Returns mac_tables[sw_num] = {mac: bmv2_port}
    - s1, s2: host ports 0..7, uplink to core on port 8
    - s11:    s1 on port 0, s2 on port 1
    """
    sw_hosts = {1: [], 2: []}
    for sw_num in EDGE_SWITCHES:
        for j in range(1, HOSTS_PER_EDGE + 1):
            mac = f"00:00:00:00:{sw_num:02x}:{j:02x}"
            sw_hosts[sw_num].append((mac, j-1))

    tables = {1: {}, 2: {}, 11: {}}

    for sw_num in EDGE_SWITCHES:
        uplink_port = HOSTS_PER_EDGE   # port 8
        for mac, port in sw_hosts[sw_num]:
            tables[sw_num][mac] = port
        other_sw = 2 if sw_num == 1 else 1
        for mac, _ in sw_hosts[other_sw]:
            tables[sw_num][mac] = uplink_port

    for mac, _ in sw_hosts[1]:
        tables[11][mac] = 0
    for mac, _ in sw_hosts[2]:
        tables[11][mac] = 1

    return tables, sw_hosts


class P4Switch(Switch):
    def __init__(self, name, sw_id, json_path=P4JSON, **kwargs):
        kwargs.setdefault('failMode', 'standalone')
        super().__init__(name, **kwargs)
        self.sw_id       = sw_id
        self.json_path   = json_path
        self.thrift_port = 9090 + (sw_id - 1) * 10
        self.log_file    = os.path.join(LOGDIR, f"{name}.log")
        self.proc        = None
        self.cpu_intf    = f"{name}-cpu0"
        self.cpu_ctrl    = f"{name}-cpu1"

    def _create_cpu_veth(self):
        os.system(f"ip link del {self.cpu_intf} 2>/dev/null || true")
        os.system(f"ip link add {self.cpu_intf} type veth peer name {self.cpu_ctrl}")
        os.system(f"ip link set {self.cpu_intf} up")
        os.system(f"ip link set {self.cpu_ctrl} up")

    def start(self, controllers):
        self._create_cpu_veth()
        iface_args = []
        port_idx = 0
        for intf in self.intfList():
            if intf.name == "lo":
                continue
            iface_args += ["-i", f"{port_idx}@{intf.name}"]
            port_idx += 1
        iface_args += ["-i", f"255@{self.cpu_intf}"]

        cmd = [
            "simple_switch",
            "--device-id",   str(self.sw_id),
            "--thrift-port", str(self.thrift_port),
            "--log-file",    self.log_file,
            "--log-flush",
            "--log-level",   "warn",
        ] + iface_args + [self.json_path]

        with open(self.log_file, "w") as lf:
            self.proc = subprocess.Popen(cmd, stdout=lf, stderr=lf, close_fds=True)

    def stop(self, deleteIntfs=True):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:    self.proc.wait(timeout=3)
            except: self.proc.kill()
        os.system(f"ip link del {self.cpu_intf} 2>/dev/null || true")
        super().stop(deleteIntfs)

    def configure(self, mac_table, switch_type):
        """
        Configure split-horizon multicast groups.
        Creates one group per data port, group_id = ingress_port + 1,
        containing all data ports EXCEPT the ingress_port.
        """
        # Manual counter to match start() exactly — do NOT use enumerate()
        data_ports = []
        port_idx = 0
        for intf in self.intfList():
            if intf.name != "lo":
                data_ports.append(port_idx)
                port_idx += 1

        num_ports = len(data_ports)

        lines = []
        lines.append(f"table_add tbl_switch_id set_switch_id => {self.sw_id}")
        lines.append("mirroring_add 100 255")

        handle = 0
        for ingress in data_ports:
            group_id = ingress + 1
            lines.append(f"mc_mgrp_create {group_id}")

            egress_ports = [p for p in data_ports if p != ingress]
            first_handle = handle
            for egress in egress_ports:
                lines.append(f"mc_node_create {handle} {egress}")
                handle += 1
            for h in range(first_handle, handle):
                lines.append(f"mc_node_associate {group_id} {h}")

        for mac, port in sorted(mac_table.items()):
            lines.append(f"table_add tbl_l2 l2_forward {mac} => {port}")

        cfg_path = os.path.join(CFGDIR, f"{self.name}_runtime.txt")
        with open(cfg_path, "w") as f:
            f.write("\n".join(lines) + "\n")

        subprocess.run(f"simple_switch_CLI --thrift-port {self.thrift_port} < {cfg_path}",
                       shell=True, capture_output=True, text=True, timeout=30)
        info(f"  [{self.name}] ✓ configured ({switch_type}) groups={num_ports} entries={len(mac_table)}\n")


def main():
    setLogLevel("info")
    cleanup()

    if not os.path.exists(P4JSON):
        error(f"\n[!] {P4JSON} not found.\n")
        sys.exit(1)

    info("\n" + "="*60)
    info("\n[TOPO] Simplified tree: s11(core) → s1,s2(edge) → 16 hosts\n")
    info("="*60 + "\n")

    info("[TOPO] Computing MAC tables...\n")
    mac_tables, _ = compute_mac_tables()

    net = Mininet(controller=None, switch=P4Switch, host=Host,
                  link=TCLink, autoSetMacs=False, autoStaticArp=False)

    info("[TOPO] Adding switches...\n")
    switches = {}
    for sw_num in ALL_SWITCH_NUMS:
        sw = net.addSwitch(f"s{sw_num}", cls=P4Switch,
                           sw_id=sw_num, json_path=P4JSON)
        switches[f"s{sw_num}"] = sw

    info("[TOPO] Adding 16 hosts (8 per edge switch)...\n")
    host_idx = 1
    for sw_num in EDGE_SWITCHES:
        for j in range(1, HOSTS_PER_EDGE + 1):
            mac = f"00:00:00:00:{sw_num:02x}:{j:02x}"
            ip  = f"10.{sw_num}.{j}.1/8"
            h = net.addHost(f"h{host_idx}", ip=ip, mac=mac)
            net.addLink(h, switches[f"s{sw_num}"])
            host_idx += 1

    info("[TOPO] Adding core links (s1‑s11, s2‑s11)...\n")
    net.addLink(switches["s1"], switches["s11"])
    net.addLink(switches["s2"], switches["s11"])

    info("\n[TOPO] Starting network...\n")
    net.start()

    info("\n[TOPO] Waiting for Thrift ports to bind...\n")
    time.sleep(5)

    info("\n[TOPO] Configuring switches...\n")
    for name, sw in switches.items():
        sw_num = int(name[1:])
        if sw_num == ROOT:
            switch_type = "core"
        else:
            switch_type = "edge"
        sw.configure(mac_tables[sw_num], switch_type)

    ifaces = " ".join(switches[f"s{i}"].cpu_ctrl for i in ALL_SWITCH_NUMS)

    info("\n" + "="*60)
    info("\n[TOPO] NETWORK READY (3 switches, 16 hosts)\n")
    info("="*60)
    info("\nTo start the controller:\n")
    info(f"  sudo python3 {BASE}/controller/controller.py \\\n")
    info(f"    --interfaces {ifaces} --label normal\n")
    info("\nConnectivity tests:\n")
    info("  Same switch:    h1 ping -c 3 10.1.2.1\n")
    info("  Cross‑edge:     h1 ping -c 3 10.2.1.1\n")
    info("="*60 + "\n")

    CLI(net)
    net.stop()


if __name__ == "__main__":
    main()