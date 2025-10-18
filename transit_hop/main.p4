#include <core.p4>
#include <v1model.p4>

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
 **************************************************************************/

typedef bit<9>  egress_spec_t;
typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;

const bit<16> TYPE_IPV4    = 0x0800;
const bit<8>  IP_PROTO_UDP = 0x11;
const bit<8>  IP_PROTO_TCP = 0x06;
const bit<32> MTU          = 1500;
const bit<16> VF_02        = 770;

// We insert exactly 4 words (16B) per hop: node_id, hop_latency, qid+occ, egress_tx
const bit<5>  HOP_WORDS    = 4;

/*************************************************************************
 *********************** H E A D E R S  ***********************************
 *************************************************************************/

header ethernet_t {
  mac_addr_t dst_addr;
  mac_addr_t src_addr;
  bit<16> type;
}

header ipv4_t {
  bit<4> version;
  bit<4> ihl;
  bit<6> dscp;
  bit<2> ecn;
  bit<16> total_len;
  bit<16> identification;
  bit<3> flags;
  bit<13> frag_offset;
  bit<8> ttl;
  bit<8> protocol;
  bit<16> hdr_checksum;
  ipv4_addr_t src_addr;
  ipv4_addr_t dst_addr;
}

header udp_t {
  bit<16> src_port;
  bit<16> dst_port;
  bit<16> length_;
  bit<16> checksum;
}

header tcp_t {
  bit<16> src_port;
  bit<16> dst_port;
  bit<32> seq_no;
  bit<32> ack_no;
  bit<4>  data_offset;
  bit<3>  res;
  bit<3>  ecn;
  bit<6>  ctrl;
  bit<16> window;
  bit<16> checksum;
  bit<16> urgent_ptr;
}

header intl4_shim_t {
  bit<4>  int_type;     // 1 = MD, 3 = MX (we expect MD here)
  bit<2>  npt;
  bit<2>  rsvd0;
  bit<8>  len;          // INT-MD header + metadata stack length in 4B words (excludes this shim)
  bit<8>  first_word_of_udp_port;
  bit<8>  reserved;     // or original L4 proto when NPT=2
}

header int_header_t {
  bit<4>  ver; bit<1> d; bit<1> e; bit<1> m; bit<12> rsvd1;
  bit<5>  hop_metadata_len;      // words per hop (must be == HOP_WORDS here)
  bit<8>  remaining_hop_cnt;
  bit<16> instruction;           // baseline bitmap (bit0 MSB .. bit15)
  bit<16> domain_specific_id;
  bit<16> ds_instruction;        // not used here, but preserved
  bit<16> ds_flags;              // may be updated by transit
}

// Fixed 16B hop metadata for our subset (4 words)
header node_metadata_t {
  bit<32> node_id;               // word 0
  bit<32> hop_latency;           // word 1
  bit<8>  queue_id;              // word 2 (high 8)
  bit<24> queue_occupancy;       // word 2 (low 24)
  bit<32> egress_interface_tx;   // word 3
}

struct headers {
  ethernet_t       ethernet;
  ipv4_t           ipv4;
  udp_t            udp;
  tcp_t            tcp;
  intl4_shim_t     intl4_shim;
  int_header_t     int_header;
  node_metadata_t  node_metadata;
}

struct meta_t {
  bit<32> node_id;
  bit<16> ingress_if;
  bit<16> egress_if;
  bit<32> hop_latency;
  bit<8>  queue_id;
  bit<24> queue_occupancy;
  bit<32> egress_interface_tx;

  // no payload varbit → no parser scratch needed
}

/*************************************************************************
 ***************************  P A R S E R  *******************************
 *************************************************************************/

parser P(packet_in p, out headers h, inout meta_t m, inout standard_metadata_t sm) {
  state start { transition parse_eth; }

  state parse_eth {
    p.extract(h.ethernet);
    transition select(h.ethernet.type) {
      TYPE_IPV4: parse_ipv4;
      default:   accept;
    }
  }

  state parse_ipv4 {
    p.extract(h.ipv4);
    transition select(h.ipv4.protocol) {
      IP_PROTO_UDP: parse_udp;
      default:      accept;
    }
  }

  state parse_udp { p.extract(h.udp); transition parse_int_gate; }

  // INT gate: only parse INT headers when the flow really carries INT
  state parse_int_gate {
    transition select(h.udp.dst_port) {
      5000:   parse_intl4_shim;   // candidate for INT
      default: accept;            // NOT INT → stop parsing; remainder auto-carried
    }
  }

  state parse_intl4_shim { p.extract(h.intl4_shim); transition parse_int_hdr; }

  state parse_int_hdr {
    p.extract(h.int_header);
    transition select(h.int_header.ver == 2 && h.intl4_shim.int_type == 1) {
      true:   accept;   // confirmed INT; payload not extracted (auto-carried)
      false:  accept;   // NOT INT after all
    }
  }
}

/*************************************************************************
 ************   C H E C K S U M    V E R I F I C A T I O N   *************
 *************************************************************************/

control Verify(inout headers h, inout meta_t m) { apply { } }

/*************************************************************************
 *************   C H E C K S U M    C O M P U T A T I O N   ***************
 *************************************************************************/

control Compute(inout headers h, inout meta_t m) {
  apply {
    update_checksum(
      h.ipv4.isValid(),
      { h.ipv4.version, h.ipv4.ihl, h.ipv4.dscp, h.ipv4.ecn, h.ipv4.total_len,
        h.ipv4.identification, h.ipv4.flags, h.ipv4.frag_offset,
        h.ipv4.ttl, h.ipv4.protocol, h.ipv4.src_addr, h.ipv4.dst_addr },
      h.ipv4.hdr_checksum, HashAlgorithm.csum16);
  }
}

/*************************************************************************
 ***************************  D E P A R S E R  ***************************
 *************************************************************************/

control D(packet_out pkt, in headers h) {
  apply {
    pkt.emit(h.ethernet);
    pkt.emit(h.ipv4);
    pkt.emit(h.udp);
    pkt.emit(h.intl4_shim);   // emits no bytes if invalid
    pkt.emit(h.int_header);   // emits no bytes if invalid
    pkt.emit(h.node_metadata);// emits no bytes if invalid
    // No payload emit; remainder of original packet is auto-carried by NFP
  }
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

control I(inout headers h, inout meta_t m, inout standard_metadata_t sm) {
  apply {
    // TODO Replace with a register so its configurable
    m.node_id    = 1001;

    m.ingress_if  = (bit<16>) sm.ingress_port;
    sm.egress_spec = VF_02;
  }
}

/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

control E(inout headers h, inout meta_t m, inout standard_metadata_t sm) {
  apply {
    // Only touch packets that actually carry INT
    if (h.ipv4.isValid() && h.intl4_shim.isValid() && h.int_header.isValid()) {

      // If no budget left: set E and do nothing else
      if (h.int_header.remaining_hop_cnt == 0) {
        h.int_header.e = 1;
        return;
      }

      // Enforce HopML == HOP_WORDS (we insert exactly 4 words)
      if (h.int_header.hop_metadata_len != HOP_WORDS) {
        h.int_header.m = 1;
        return;
      }

      // Measurements (plug real sources)
      m.egress_if           = (bit<16>) sm.egress_spec;
      bit<32> deq_delta = (bit<32>) sm.deq_timedelta; // ns on BMv2
      m.hop_latency = (bit<32>) deq_delta;  // good per-hop approximation on BMv2

      // Size/MTU guard
      bit<32> bytes_to_add = (bit<32>) HOP_WORDS * 4;         // 16 bytes
      bit<32> new_ipv4_len = (bit<32>) h.ipv4.total_len + bytes_to_add;
      if (new_ipv4_len > MTU || new_ipv4_len > 0xFFFF) {
        h.int_header.m = 1;
        return;
      }

      // Compose fixed 4-word metadata, gating with instruction bits
      bit<16> ib = h.int_header.instruction;

      h.node_metadata.setValid();

      // word 0: node_id
      h.node_metadata.node_id =
        ((ib & 0x8000) != 0) ? m.node_id : (bit<32>)0;

      // word 1: hop_latency
      h.node_metadata.hop_latency =
        ((ib & 0x2000) != 0) ? m.hop_latency : (bit<32>)0;

      // word 2: queue_id (high 8) + queue_occupancy (low 24)
      if ((ib & 0x1000) != 0) {  // if you gated on queue info in instruction bitmap
          m.queue_id        = (bit<8>) 0;
          m.queue_occupancy = (bit<24>) sm.deq_qdepth;
      } else {
          m.queue_id        = 0;
          m.queue_occupancy = 0;
      }

      // word 3: egress interface TX
      h.node_metadata.egress_interface_tx =
        ((ib & 0x0100) != 0) ? (bit<32>)sm.egress_port : (bit<32>)0;

      // INT accounting
      h.int_header.remaining_hop_cnt = h.int_header.remaining_hop_cnt - 1;
      h.intl4_shim.len               = h.intl4_shim.len + (bit<8>) HOP_WORDS;
      h.ipv4.total_len               = (bit<16>) new_ipv4_len;
      h.udp.length_                  = (bit<16>) ((bit<32>)h.udp.length_ + bytes_to_add);

      // If not recomputing, zero UDP checksum (legal for IPv4)
      h.udp.checksum = 0;
    }
  }
}

/*************************************************************************
 *****************************  S W I T C H  *****************************
 *************************************************************************/
V1Switch(P(), Verify(), I(), E(), Compute(), D()) main;
