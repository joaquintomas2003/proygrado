#include <core.p4>
#include <v1model.p4>

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
 **************************************************************************/

typedef bit<9> egress_spec_t;
typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;

const bit<16> TYPE_IPV4 = 0x0800;
const bit<6> DSCP_INT = 0x17;
const bit<6> DSCP_MASK = 0x3F;
const bit<8> IP_PROTO_UDP = 0x11;
const bit<8> IP_PROTO_TCP = 0x6;

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
  bit<6> udp_ip_dscp;            // depends on npt field. either original dscp, ip protocol or udp dest port
  bit<10> udp_ip;                // depends on npt field. either original dscp, ip protocol or udp dest port
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

header stack_element_t {
  bit<32> data;
}

struct metadata {
  bit<8> counter;             // Counter for stack elements
  bit<8>  stack_size;          // Size of the INT stack
}

struct headers {
  ethernet_t ethernet;
  ipv4_t ipv4;
  udp_t udp;
  tcp_t tcp;

  int_header_t                int_header;
  intl4_shim_t                intl4_shim;
  stack_element_t[2]          int_stack;
}

/*************************************************************************
 *********************** P A R S E R  ***********************************
 *************************************************************************/

parser MyParser(packet_in packet,
    out headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata) {

  state start {
    transition parse_ethernet;
  }

  state parse_ethernet {
    packet.extract(hdr.ethernet);
    transition select(hdr.ethernet.type) {
      TYPE_IPV4: parse_ipv4;
      default: accept;
    }
  }

  state parse_ipv4 {
    packet.extract(hdr.ipv4);
    transition select(hdr.ipv4.protocol) {
      IP_PROTO_UDP: parse_udp;
      default: accept;
    }
  }

  state parse_udp {
    packet.extract(hdr.udp);
    transition select(hdr.udp.dst_port) {
      5000: parse_shim;
      default:  accept;
    }
  }

  state parse_shim {
    packet.extract(hdr.intl4_shim);
    meta.stack_size = hdr.intl4_shim.len - 3; // 3-4 bytes for int header
    transition parse_int_hdr;
  }

  state parse_int_hdr {
    packet.extract(hdr.int_header);
    meta.counter = 0;
    transition parse_stack;
  }

  state parse_stack {
    transition select(meta.counter < meta.stack_size) {
      true: parse_stack_element;
      false: accept;
    }
  }

  state parse_stack_element {
    packet.extract(hdr.int_stack.next);
    meta.counter = meta.counter + 1;
    transition parse_stack;
  }
}

/*************************************************************************
 ************   C H E C K S U M    V E R I F I C A T I O N   *************
 *************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
  apply {  }
}

/*************************************************************************
 *************   C H E C K S U M    C O M P U T A T I O N   ***************
 *************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
  apply {
    update_checksum(
      hdr.ipv4.isValid(),
      { hdr.ipv4.version,
      hdr.ipv4.ihl,
      hdr.ipv4.dscp,
      hdr.ipv4.ecn,
      hdr.ipv4.total_len,
      hdr.ipv4.identification,
      hdr.ipv4.flags,
      hdr.ipv4.frag_offset,
      hdr.ipv4.ttl,
      hdr.ipv4.protocol,
      hdr.ipv4.src_addr,
      hdr.ipv4.dst_addr },
      hdr.ipv4.hdr_checksum,
      HashAlgorithm.csum16);
  }
}

/*************************************************************************
 ***********************  D E P A R S E R  *******************************
 *************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
  apply {
    packet.emit(hdr.ethernet);
    packet.emit(hdr.ipv4);
    packet.emit(hdr.udp);
    packet.emit(hdr.intl4_shim);
    packet.emit(hdr.int_header);
    packet.emit(hdr.int_stack);
  }
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

control MyIngress(inout headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata) {

  action drop() { }

  action ipv4_forward(mac_addr_t dst_addr, egress_spec_t port) {
    if (hdr.ipv4.ttl > 0) {
      hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
      hdr.ethernet.dst_addr = dst_addr;
      hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
  }

  table ipv4_lpm {
    key = {
      hdr.ipv4.dst_addr: lpm;
    }
    actions = {
      ipv4_forward;
      drop;
      NoAction;
    }
    size = 1024;
    default_action = drop();
  }

  apply {
    if (hdr.ipv4.isValid()) {
      ipv4_lpm.apply();
    }
  }
}

/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

control MyEgress(inout headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata) {
  apply {  }
}

/*************************************************************************
 ***********************  S W I T C H  *******************************
 *************************************************************************/

V1Switch(
  MyParser(),
  MyVerifyChecksum(),
  MyIngress(),
  MyEgress(),
  MyComputeChecksum(),
  MyDeparser()
) main;
