/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 0x06;
const bit<8>  TYPE_UDP  = 0x11;

header ethernet_t {
  bit<48> dstAddr;
  bit<48> srcAddr;
  bit<16> etherType;
}

header ipv4_t {
  bit<4>  version;
  bit<4>  ihl;
  bit<8>  diffserv;
  bit<16> totalLen;
  bit<16> identification;
  bit<3>  flags;
  bit<13> fragOffset;
  bit<8>  ttl;
  bit<8>  protocol;
  bit<16> hdrChecksum;
  bit<32> srcAddr;
  bit<32> dstAddr;
}

header tcp_t {
  bit<16> srcPort;
  bit<16> dstPort;
  bit<32> seqNo;
  bit<32> ackNo;
  bit<4>  dataOffset;
  bit<4>  res;
  bit<8>  flags;
  bit<16> window;
  bit<16> checksum;
  bit<16> urgentPtr;
}

header udp_t {
  bit<16> srcPort;
  bit<16> dstPort;
  bit<16> length;
  bit<16> checksum;
}

header nfp_mac_eg_cmd_t {
  bit l3Sum;        // Enable L3 checksum computation
  bit l4Sum;        // Enable L4 checksum computation
  bit tsMark;       // Enable Timestamp marking on egress
  bit<29> ignore;
}

// Extracted from INT specification 2.1 page 17 - 5.7
header int_shim {
  bit<4> type; // This field indicates the type of INT Header following the shim header
  bit<2> ntp; // Next Protocol Type
  bit<8> length; // This is the total length of INT metadata header and INT stack in 4-byte words.
  bit<16> udpPort;
}

// Extracted from INT specification 2.1 page 20 - 5.8
header int {
  bit<4> version;
  bit D; // Discard flag
  bit E; // Max Hop Count exceeded.
  bit M; // MTU exceeded
  bit<12> R; // Reserved bits, should be set to 0 by the INT source and ignored by other nodes.
  bit<5> hopML; // Per-hop Metadata Length. This is the length of metadata including the Domain Specific Metadata in 4-Byte words to be inserted at each INT transit hop.
  bit<8> remainingHopCount; // The remaining number of hops that are allowed to add their metadata to the packet
  bit<16> intstructionType; // Instruction Bitmap, see page 22 of INT specification 2.1
  bit<16> domainSpecificId; // Domain Specific ID The unique ID of the INT Domain
  bit<16> DSInstruction; // Instruction bitmap specific to the INT domain identified by the Domain Specific ID
  bit<16> DSFlags;
}

// Extracted from INT specification 2.1 page 22 - 5.8
header int_metadata {
  bit<32> hopId; // Hop ID
  bit<16> level1IngressInterfaceId;
  bit<16> level1egressInterfaceId;
  bit<32> hopLatency;
  bit<8> queueId;
  bit<24> queueOccupancy;
  bit<64> ingressTimestamp;
  bit<64> egressTimestamp;
  bit<32> level2IngressInterfaceId;
  bit<32> level2EgressInterfaceId;
  bit<32> egressInterfaceTx;
  bit<8> bufferId;
  bit<24> bufferOccupancy;
  bit<32> checksumComplement;
}

struct headers_t {
  nfp_mac_eg_cmd_t nfp_mac_eg_cmd;
  ethernet_t ethernet;
  ipv4_t ipv4;
}

struct metadata_t {
  /* empty */
}
