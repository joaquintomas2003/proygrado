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
  bit<4> int_type;                // Type of INT Header
  bit<2> npt;                     // Next protocol type
  bit<2> rsvd;                    // Reserved
  bit<8> len;                     // Length of INT Metadata header and INT stack in 4-byte words, not including the shim header (1 word)
  bit<8> first_word_of_udp_port;  // First word of the UDP port used when NPT = 1
  bit<8> reserved;                // Second word of the UDP port used when NPT = 1 or the original protocol type when NPT = 2
}

header int_header_t {
  bit<4> ver;                    // Version
  bit<1> d;                      // Discard
  bit<1> e;
  bit<1> m;
  bit<12> rsvd1;
  bit<5> hop_metadata_len;
  bit<8> remaining_hop_cnt;
  bit<16> instruction;
  bit<16> domain_specific_id;     // Unique INT Domain ID
  bit<16> ds_instruction;         // Instruction bitmap specific to the INT Domain identified by the Domain specific ID
  bit<16> ds_flags;               // Domain specific flags
}

header intw_t { bit<32> v; }

struct headers {
  ethernet_t   ethernet;
  ipv4_t       ipv4;
  udp_t        udp;
  tcp_t        tcp;
  intl4_shim_t intl4_shim;
  int_header_t int_header;

  intw_t int_w1;
  intw_t int_w2;
  intw_t int_w3;
  intw_t int_w4;
  intw_t int_w5;
  intw_t int_w6;
  intw_t int_w7;
  intw_t int_w8;
  intw_t int_w9;
  intw_t int_w10;
  intw_t int_w11;
  intw_t int_w12;
}

struct meta_t {
  bit<32> node_id;
  bit<16> ingress_if;
  bit<16> egress_if;
  bit<32> hop_latency;
  bit<8>  queue_id;
  bit<24> queue_occupancy;
  bit<32> egress_interface_tx;
}

/*************************************************************************
 ***************************  P A R S E R  *******************************
 *************************************************************************/

parser MyParser(packet_in p, out headers h, inout meta_t m, inout standard_metadata_t sm) {
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

control MyVerifyChecksum(inout headers h, inout meta_t m) { apply { } }

/*************************************************************************
 *************   C H E C K S U M    C O M P U T A T I O N   ***************
 *************************************************************************/

control MyComputeChecksum(inout headers h, inout meta_t m) {
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

control MyDeparser(packet_out pkt, in headers h) {
  apply {
    pkt.emit(h.ethernet);
    pkt.emit(h.ipv4);
    pkt.emit(h.udp);
    pkt.emit(h.intl4_shim);
    pkt.emit(h.int_header);
    pkt.emit(h.int_w1);
    pkt.emit(h.int_w2);
    pkt.emit(h.int_w3);
    pkt.emit(h.int_w4);
    pkt.emit(h.int_w5);
    pkt.emit(h.int_w6);
    pkt.emit(h.int_w7);
    pkt.emit(h.int_w8);
    pkt.emit(h.int_w9);
    pkt.emit(h.int_w10);
    pkt.emit(h.int_w11);
    pkt.emit(h.int_w12);
  }
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

control MyIngress(inout headers h, inout meta_t m, inout standard_metadata_t sm) {
  apply {
    m.node_id = 1001;
    if (sm.ingress_port == 0)      { sm.egress_spec = 1; }
    else if (sm.ingress_port == 1) { sm.egress_spec = 0; }
  }
}

/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

control MyEgress(inout headers h, inout meta_t m, inout standard_metadata_t sm) {
  apply {
    if (h.ipv4.isValid() && h.intl4_shim.isValid() && h.int_header.isValid()) {
      if (h.int_header.remaining_hop_cnt == 0) { h.int_header.e = 1; return; }

      bit<16> l1_ing_if = (bit<16>) sm.ingress_port;
      bit<16> l1_egr_if = (bit<16>) sm.egress_spec;
      bit<32> level1_if = (bit<32>) (((bit<32>)l1_ing_if << 16) | (bit<32>)l1_egr_if);
      bit<32> hop_latency = (bit<32>) sm.deq_timedelta;
      bit<8>  qid = 0;
      bit<32> qocc = (bit<32>) (bit<24>) sm.deq_qdepth;
      bit<32> queue_word = (bit<32>) (((bit<32>)qid << 24) | qocc);
      bit<64> ts_in_64 = (bit<64>) sm.ingress_global_timestamp;
      bit<64> ts_eg_64 = (bit<64>) sm.egress_global_timestamp;
      bit<32> ts_in_hi = (bit<32>) (ts_in_64 >> 32);
      bit<32> ts_in_lo = (bit<32>) (ts_in_64 & 0xFFFF_FFFF);
      bit<32> ts_eg_hi = (bit<32>) (ts_eg_64 >> 32);
      bit<32> ts_eg_lo = (bit<32>) (ts_eg_64 & 0xFFFF_FFFF);
      bit<32> egress_tx = (bit<32>) sm.egress_port;
      bit<32> l2_ing_if = 0;
      bit<32> l2_egr_if = 0;

      bit<16> ib = h.int_header.instruction;
      bit<5> req = (bit<5>) h.int_header.hop_metadata_len;

      h.int_w1.setInvalid();  h.int_w2.setInvalid();  h.int_w3.setInvalid();
      h.int_w4.setInvalid();  h.int_w5.setInvalid();  h.int_w6.setInvalid();
      h.int_w7.setInvalid();  h.int_w8.setInvalid();  h.int_w9.setInvalid();
      h.int_w10.setInvalid(); h.int_w11.setInvalid(); h.int_w12.setInvalid();

      bit<32> w1 = (((ib >> 15) & 1) == 1) ? m.node_id    : (bit<32>)0;
      bit<32> w2 = (((ib >> 13) & 1) == 1) ? hop_latency : (bit<32>)0;
      bit<32> w3 = (((ib >> 12) & 1) == 1) ? queue_word  : (bit<32>)0;
      bit<32> w4 = (((ib >>  8) & 1) == 1) ? egress_tx   : (bit<32>)0;
      bit<32> w5 = (((ib >> 14) & 1) == 1) ? level1_if   : (bit<32>)0;
      bit<32> w6 = (((ib >> 11) & 1) == 1) ? ts_in_hi    : (bit<32>)0;
      bit<32> w7 = (((ib >> 11) & 1) == 1) ? ts_in_lo    : (bit<32>)0;
      bit<32> w8 = (((ib >> 10) & 1) == 1) ? ts_eg_hi    : (bit<32>)0;
      bit<32> w9 = (((ib >> 10) & 1) == 1) ? ts_eg_lo    : (bit<32>)0;
      bit<32> w10 = (((ib >>  9) & 1) == 1) ? l2_ing_if  : (bit<32>)0;
      bit<32> w11 = (((ib >>  9) & 1) == 1) ? l2_egr_if  : (bit<32>)0;
      bit<32> w12 = (((ib >>  7) & 1) == 1) ? (bit<32>) sm.enq_qdepth : (bit<32>)0;

      if (req > 0) { h.int_w1.setValid();  h.int_w1.v  = w1; }
      if (req > 1) { h.int_w2.setValid();  h.int_w2.v  = w2; }
      if (req > 2) { h.int_w3.setValid();  h.int_w3.v  = w3; }
      if (req > 3) { h.int_w4.setValid();  h.int_w4.v  = w4; }
      if (req > 4) { h.int_w5.setValid();  h.int_w5.v  = w5; }
      if (req > 5) { h.int_w6.setValid();  h.int_w6.v  = w6; }
      if (req > 6) { h.int_w7.setValid();  h.int_w7.v  = w7; }
      if (req > 7) { h.int_w8.setValid();  h.int_w8.v  = w8; }
      if (req > 8) { h.int_w9.setValid();  h.int_w9.v  = w9; }
      if (req > 9) { h.int_w10.setValid(); h.int_w10.v = w10; }
      if (req > 10){ h.int_w11.setValid(); h.int_w11.v = w11; }
      if (req > 11){ h.int_w12.setValid(); h.int_w12.v = w12; }

      bit<32> bytes_add = (bit<32>) req * 4;
      bit<32> new_len   = (bit<32>) h.ipv4.total_len + bytes_add;
      if (new_len > 1500 || new_len > 0xFFFF) { h.int_header.m = 1; return; }

      h.int_header.remaining_hop_cnt = h.int_header.remaining_hop_cnt - 1;
      h.intl4_shim.len = h.intl4_shim.len + (bit<8>) req;
      h.ipv4.total_len = (bit<16>) new_len;
      h.udp.length_    = (bit<16>) ((bit<32>) h.udp.length_ + bytes_add);
      h.udp.checksum   = 0;
    }
  }
}

/*************************************************************************
 *****************************  S W I T C H  *****************************
 *************************************************************************/
V1Switch(
  MyParser(),
  MyVerifyChecksum(),
  MyIngress(),
  MyEgress(),
  MyComputeChecksum(),
  MyDeparser()
  ) main;
