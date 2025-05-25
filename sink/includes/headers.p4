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
    bit<4> instruction_mask_0003; /* split the bits for lookup */
    bit<4> instruction_mask_0407;
    bit<4> instruction_mask_0811;
    bit<4> instruction_mask_1215;
    bit<16> domain_specific_id;     // Unique INT Domain ID
    bit<16> ds_instruction;         // Instruction bitmap specific to the INT Domain identified by the Domain specific ID
    bit<16> ds_flags;               // Domain specific flags
}

header int_switch_id_t {
    bit<32> switch_id;
}

header int_level1_port_ids_t {
    bit<16> ingress_port_id;
    bit<16> egress_port_id;
}

header int_hop_latency_t {
    bit<32> hop_latency;
}

header int_q_occupancy_t {
    bit<8> q_id;
    bit<24> q_occupancy;
}

header int_ingress_tstamp_t {
    bit<64> ingress_tstamp;
}

header int_egress_tstamp_t {
    bit<64> egress_tstamp;
}

header int_level2_port_ids_t {
    bit<32> ingress_port_id;
    bit<32> egress_port_id;
}

header int_egress_port_tx_util_t {
    bit<32> egress_port_tx_util;
}

header int_buffer_t {
    bit<8> buffer_id;
    bit<24> buffer_occupancy;
}

struct headers {
  ethernet_t ethernet;
  ipv4_t ipv4;
  udp_t udp;
  tcp_t tcp;

  int_header_t                int_header;
  intl4_shim_t                intl4_shim;
  int_switch_id_t             int_switch_id;
  int_level1_port_ids_t       int_level1_port_ids;
  int_hop_latency_t           int_hop_latency;
  int_q_occupancy_t           int_q_occupancy;
  int_ingress_tstamp_t        int_ingress_tstamp;
  int_egress_tstamp_t         int_egress_tstamp;
  int_level2_port_ids_t       int_level2_port_ids;
  int_egress_port_tx_util_t   int_egress_tx_util;
}

struct metadata {
    /* empty */
}
