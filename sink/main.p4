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
const bit<8> MAX_INT_NODES = 5;
const bit<5> ENTRY_LEN = 1; // one 32-bit word per `next` header

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

  /* Number of node metadata blocks present in this packet */
  bit<8> nodes_present;

  /* Per-node entry counters used while looping */
  bit<5> node1_entries;
  bit<5> node2_entries;
  bit<5> node3_entries;
  bit<5> node4_entries;
  bit<5> node5_entries;
}

struct headers {
  ethernet_t ethernet;
  ipv4_t ipv4;
  udp_t udp;
  tcp_t tcp;

  int_header_t                int_header;
  intl4_shim_t                intl4_shim;
  stack_element_t[12]          node1_metadata;
  stack_element_t[12]          node2_metadata;
  stack_element_t[12]          node3_metadata;
  stack_element_t[12]          node4_metadata;
  stack_element_t[12]          node5_metadata;
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
    meta.stack_size = hdr.intl4_shim.len - 3;
    transition parse_int_header;
  }

  state parse_int_header {
    packet.extract(hdr.int_header);

    /* INT spec: RemainingHopCnt = unused nodes; we parse up to MAX_INT_NODES */
    meta.nodes_present = MAX_INT_NODES - hdr.int_header.remaining_hop_cnt;

    meta.node1_entries = 0;
    meta.node2_entries = 0;
    meta.node3_entries = 0;
    meta.node4_entries = 0;
    meta.node5_entries = 0;

    transition select(meta.nodes_present > 0) {
      true: parse_node1_entry;
      false: accept;
    }
  }

  /* ---------- Node 1 ---------- */
  state parse_node1_entry {
    packet.extract(hdr.node1_metadata.next);
    meta.node1_entries = meta.node1_entries + ENTRY_LEN;
    transition parse_node1_loop;
  }

  state parse_node1_loop {
    transition select(meta.node1_entries < hdr.int_header.hop_metadata_len) {
      true  : parse_node1_entry;
      false : parse_node1_after;
    }
  }

  state parse_node1_after {
    transition select(meta.nodes_present){
      1: accept;
      default: parse_node2_entry;
    }
  }

  /* ---------- Node 2 ---------- */
  state parse_node2_entry {
    packet.extract(hdr.node2_metadata.next);
    meta.node2_entries = meta.node2_entries + ENTRY_LEN;
    transition parse_node2_loop;
  }

  state parse_node2_loop {
    transition select(meta.node2_entries < hdr.int_header.hop_metadata_len) {
      true  : parse_node2_entry;
      false : parse_node2_after;
    }
  }

  state parse_node2_after {
    transition select(meta.nodes_present){
      2: accept;
      default: parse_node3_entry;
    }
  }

  /* ---------- Node 3 ---------- */
  state parse_node3_entry {
    packet.extract(hdr.node3_metadata.next);
    meta.node3_entries = meta.node3_entries + ENTRY_LEN;
    transition parse_node3_loop;
  }

  state parse_node3_loop {
    transition select(meta.node3_entries < hdr.int_header.hop_metadata_len) {
      true  : parse_node3_entry;
      false : parse_node3_after;
    }
  }

  state parse_node3_after {
    transition select(meta.nodes_present){
      3: accept;
      default: parse_node4_entry;
    }
  }

  /* ---------- Node 4 ---------- */
  state parse_node4_entry {
    packet.extract(hdr.node4_metadata.next);
    meta.node4_entries = meta.node4_entries + ENTRY_LEN;
    transition parse_node4_loop;
  }

  state parse_node4_loop {
    transition select(meta.node4_entries < hdr.int_header.hop_metadata_len) {
      true  : parse_node4_entry;
      false : parse_node4_after;
    }
  }

  state parse_node4_after {
    transition select(meta.nodes_present){
      4: accept;
      default: parse_node5_entry;
    }
  }

  /* ---------- Node 5 ---------- */
  state parse_node5_entry {
    packet.extract(hdr.node5_metadata.next);
    meta.node5_entries = meta.node5_entries + ENTRY_LEN;
    transition parse_node5_loop;
  }

  state parse_node5_loop {
    transition select(meta.node5_entries < hdr.int_header.hop_metadata_len) {
      true  : parse_node5_entry;
      false : accept;
    }
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
    packet.emit(hdr.node1_metadata);
    packet.emit(hdr.node2_metadata);
    packet.emit(hdr.node3_metadata);
    packet.emit(hdr.node4_metadata);
    packet.emit(hdr.node5_metadata);
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
