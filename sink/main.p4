#include <core.p4>
#include <v1model.p4>
#include "includes/headers.p4"

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
            IP_PROTO_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.ipv4.dscp) {
            DSCP_INT &&& DSCP_MASK: parse_shim;
            default:  accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition select(hdr.ipv4.dscp) {
            DSCP_INT &&& DSCP_MASK: parse_shim;
            default:  accept;
        }
    }

    state parse_shim {
        packet.extract(hdr.intl4_shim);
        transition parse_int_hdr;
    }

    state parse_int_hdr {
        packet.extract(hdr.int_header);
        transition parse_int_data;
    }

    state parse_int_data {
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
    }

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
    packet.emit(hdr.tcp);
    packet.emit(hdr.intl4_shim);
    packet.emit(hdr.int_header);
  }
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
