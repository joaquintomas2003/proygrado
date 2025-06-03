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
  }
}
