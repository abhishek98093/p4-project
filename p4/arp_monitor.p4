/* ============================================================
 * arp_monitor.p4  —  ARP Flood Detection, P4_16 v1model / BMv2
 *
 * Forwarding logic:
 *   ARP broadcast  → split-horizon flood via per-ingress-port
 *                    multicast group (excludes ingress port)
 *   ARP unicast    → tbl_l2 lookup (replies go directly to requester)
 *   IP/ICMP/other  → tbl_l2 lookup → forward to correct port
 *   Unknown MAC    → drop (no IP flooding)
 *
 * Monitoring logic:
 *   Every ARP packet → classify + increment 5 registers + sample counter
 *   Every 10th ARP  → snapshot registers, reset to 0, clone to CPU port 255
 *   Cloned packet   → egress prepends cpu_header_t (41 bytes)
 *
 * Flood design (split-horizon):
 *   Multicast group (ingress_port + 1) contains every port EXCEPT
 *   ingress_port.  This makes loop prevention a data-plane property:
 *   no packet is ever sent back toward the link it arrived on, so a
 *   tree topology is guaranteed loop-free without any egress check.
 *   An egress safety-net drop is kept as defence-in-depth.
 * ============================================================ */

#include <core.p4>
#include <v1model.p4>

const bit<16> ETHERTYPE_ARP  = 0x0806;
const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ARP_OP_REQUEST = 1;
const bit<16> ARP_OP_REPLY   = 2;
const bit<48> BROADCAST_MAC  = 0xFFFFFFFFFFFF;
const bit<9>  CPU_PORT       = 255;
const bit<8>  SAMPLE_EVERY   = 10;
const bit<32> CLONE_SESSION  = 100;

// ── Headers ───────────────────────────────────────────────────────────────────

header ethernet_t {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3>  flags;
    bit<13> frag_offset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

header arp_t {
    bit<16> hw_type;
    bit<16> proto_type;
    bit<8>  hw_len;
    bit<8>  proto_len;
    bit<16> opcode;
    bit<48> sender_mac;
    bit<32> sender_ip;
    bit<48> target_mac;
    bit<32> target_ip;
}

// cpu_header_t — prepended ONLY on cloned packets going to CPU_PORT
// Total: 1+1+2+4+6+4+2+4+4+4+4+4+1 = 41 bytes
header cpu_header_t {
    bit<8>  reason;
    bit<8>  switch_id;
    bit<9>  ingress_port;
    bit<7>  _pad;
    bit<32> sender_ip;
    bit<48> sender_mac;
    bit<32> target_ip;
    bit<16> opcode;
    bit<32> reg_arp_total;
    bit<32> reg_arp_request;
    bit<32> reg_arp_reply;
    bit<32> reg_gratuitous;
    bit<32> reg_broadcast;
    bit<8>  reg_sample_counter;
}

struct headers_t {
    cpu_header_t cpu_hdr;
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    arp_t        arp;
}

// ALL fields annotated @field_list(0) so they survive clone into egress
struct metadata_t {
    @field_list(0) bit<8>  switch_id;
    @field_list(0) bit<1>  do_clone;
    @field_list(0) bit<7>  _pad;
    @field_list(0) bit<32> snap_total;
    @field_list(0) bit<32> snap_request;
    @field_list(0) bit<32> snap_reply;
    @field_list(0) bit<32> snap_gratuitous;
    @field_list(0) bit<32> snap_broadcast;
    @field_list(0) bit<8>  snap_counter;
}

// ── Registers ─────────────────────────────────────────────────────────────────
register<bit<32>>(1) reg_arp_total;
register<bit<32>>(1) reg_arp_request;
register<bit<32>>(1) reg_arp_reply;
register<bit<32>>(1) reg_gratuitous;
register<bit<32>>(1) reg_broadcast;
register<bit<8>>(1)  reg_sample_counter;

// ── Parser ────────────────────────────────────────────────────────────────────
parser MyParser(packet_in        pkt,
                out headers_t    hdr,
                inout metadata_t meta,
                inout standard_metadata_t std_meta)
{
    state start { transition parse_ethernet; }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_ARP  : parse_arp;
            ETHERTYPE_IPV4 : parse_ipv4;
            default        : accept;
        }
    }
    state parse_arp  { pkt.extract(hdr.arp);  transition accept; }
    state parse_ipv4 { pkt.extract(hdr.ipv4); transition accept; }
}

control MyVerifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

// ── Ingress ───────────────────────────────────────────────────────────────────
control MyIngress(inout headers_t    hdr,
                  inout metadata_t   meta,
                  inout standard_metadata_t std_meta)
{
    action set_switch_id(bit<8> sw_id) { meta.switch_id = sw_id; }
    table tbl_switch_id {
        actions        = { set_switch_id; }
        default_action = set_switch_id(0);
        size           = 1;
    }

    action l2_forward(bit<9> port) { std_meta.egress_spec = port; }
    action drop()                  { mark_to_drop(std_meta); }

    table tbl_l2 {
        key            = { hdr.ethernet.dst_addr : exact; }
        actions        = { l2_forward; drop; }
        default_action = drop();
        size           = 1024;
    }

    apply {
        tbl_switch_id.apply();

        // Always initialize do_clone to 0 — prevents spurious clones
        meta.do_clone = 0;

        if (hdr.arp.isValid()) {
            // ── ARP monitoring ────────────────────────────────────────────
            bit<1> is_request    = (hdr.arp.opcode == ARP_OP_REQUEST)       ? 1w1 : 1w0;
            bit<1> is_reply      = (hdr.arp.opcode == ARP_OP_REPLY)         ? 1w1 : 1w0;
            bit<1> is_gratuitous = (hdr.arp.sender_ip == hdr.arp.target_ip) ? 1w1 : 1w0;
            bit<1> is_broadcast  = (hdr.ethernet.dst_addr == BROADCAST_MAC) ? 1w1 : 1w0;

            bit<32> cur_total; bit<32> cur_req; bit<32> cur_rep;
            bit<32> cur_grat;  bit<32> cur_bcast; bit<8> cur_ctr;

            reg_arp_total.read(cur_total,    0);
            reg_arp_request.read(cur_req,    0);
            reg_arp_reply.read(cur_rep,      0);
            reg_gratuitous.read(cur_grat,    0);
            reg_broadcast.read(cur_bcast,    0);
            reg_sample_counter.read(cur_ctr, 0);

            cur_total = cur_total + 1;
            cur_ctr   = cur_ctr   + 1;
            if (is_request    == 1) { cur_req   = cur_req   + 1; }
            if (is_reply      == 1) { cur_rep   = cur_rep   + 1; }
            if (is_gratuitous == 1) { cur_grat  = cur_grat  + 1; }
            if (is_broadcast  == 1) { cur_bcast = cur_bcast + 1; }

            // Every 10th ARP: snapshot, reset, schedule clone
            if (cur_ctr == SAMPLE_EVERY) {
                meta.snap_total      = cur_total;
                meta.snap_request    = cur_req;
                meta.snap_reply      = cur_rep;
                meta.snap_gratuitous = cur_grat;
                meta.snap_broadcast  = cur_bcast;
                meta.snap_counter    = cur_ctr;
                meta.do_clone        = 1;
                cur_total = 0; cur_req   = 0; cur_rep   = 0;
                cur_grat  = 0; cur_bcast = 0; cur_ctr   = 0;
            }

            reg_arp_total.write(0,       cur_total);
            reg_arp_request.write(0,     cur_req);
            reg_arp_reply.write(0,       cur_rep);
            reg_gratuitous.write(0,      cur_grat);
            reg_broadcast.write(0,       cur_bcast);
            reg_sample_counter.write(0,  cur_ctr);

            if (meta.do_clone == 1) {
                clone_preserving_field_list(CloneType.I2E, CLONE_SESSION, 0);
            }

            // ── ARP forwarding ────────────────────────────────────────────
            // Split-horizon flood: group (ingress_port + 1) already
            // excludes the ingress port, so loops are structurally
            // impossible regardless of egress behaviour.
            if (hdr.ethernet.dst_addr == BROADCAST_MAC) {
                std_meta.mcast_grp = (bit<16>)std_meta.ingress_port + 1;
            } else {
                tbl_l2.apply();
            }

        } else {
            // ── Non-ARP forwarding ───────────────────────────────────────
            tbl_l2.apply();
        }
    }
}

// ── Egress ────────────────────────────────────────────────────────────────────
control MyEgress(inout headers_t    hdr,
                 inout metadata_t   meta,
                 inout standard_metadata_t std_meta)
{
    apply {
        // Safety-net: drop any multicast copy that somehow targets the
        // ingress port (should never happen with split-horizon groups,
        // but defence-in-depth costs nothing).
        if (std_meta.egress_port == std_meta.ingress_port) {
            mark_to_drop(std_meta);
            return;
        }

        // Only the cloned copy (port 255) gets the cpu_header
        if (std_meta.egress_port == CPU_PORT) {
            hdr.cpu_hdr.setValid();
            hdr.cpu_hdr.reason             = 0xAA;
            hdr.cpu_hdr.switch_id          = meta.switch_id;
            hdr.cpu_hdr.ingress_port       = std_meta.ingress_port;
            hdr.cpu_hdr._pad               = 0;
            hdr.cpu_hdr.sender_ip          = hdr.arp.sender_ip;
            hdr.cpu_hdr.sender_mac         = hdr.arp.sender_mac;
            hdr.cpu_hdr.target_ip          = hdr.arp.target_ip;
            hdr.cpu_hdr.opcode             = hdr.arp.opcode;
            hdr.cpu_hdr.reg_arp_total      = meta.snap_total;
            hdr.cpu_hdr.reg_arp_request    = meta.snap_request;
            hdr.cpu_hdr.reg_arp_reply      = meta.snap_reply;
            hdr.cpu_hdr.reg_gratuitous     = meta.snap_gratuitous;
            hdr.cpu_hdr.reg_broadcast      = meta.snap_broadcast;
            hdr.cpu_hdr.reg_sample_counter = meta.snap_counter;
        }
    }
}

control MyComputeChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

// ── Deparser ──────────────────────────────────────────────────────────────────
control MyDeparser(packet_out pkt, in headers_t hdr) {
    apply {
        pkt.emit(hdr.cpu_hdr);
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.arp);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
