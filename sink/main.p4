#include <core.p4>
#include <v1model.p4>
#include "includes/headers.p4"
#include "includes/parsers.p4"

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
