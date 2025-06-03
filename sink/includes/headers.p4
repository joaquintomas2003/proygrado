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
