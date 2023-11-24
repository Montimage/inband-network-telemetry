/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*************************************************************************
 *********************** H E A D E R S  ***********************************
 *************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
   macAddr_t dstAddr;
   macAddr_t srcAddr;
   bit<16>   etherType;
}

header ipv4_t {
   bit<4>    version;
   bit<4>    ihl;
   bit<6>    dscp;
   bit<2>    ecn;
   bit<16>   totalLen;
   bit<16>   identification;
   bit<3>    flags;
   bit<13>   fragOffset;
   bit<8>    ttl;
   bit<8>    protocol;
   bit<16>   hdrChecksum;
   ip4Addr_t srcAddr;
   ip4Addr_t dstAddr;
}


struct metadata {
   /* empty */
}

struct headers {
   ethernet_t  ethernet;
   ipv4_t      ipv4;
}

/*************************************************************************
 *********************** P A R S E R  ***********************************
 *************************************************************************/

parser MyParser(packet_in packet,
      out headers hdr,
      inout metadata meta,
      inout standard_metadata_t standard_metadata) {
   bit<4> tcp_opt_cnt = 0;
   state start {
      transition select(standard_metadata.ingress_port) {
          2: parse_ethernet; //port 2: Ethernet
          1: parse_ipv4;     //port 1: IP (TUN)
      }
   }

   state parse_ethernet {
      packet.extract(hdr.ethernet);
      transition select(hdr.ethernet.etherType) {
         0x800  : parse_ipv4;
         default: accept;
      }
   }
   state parse_ipv4 {
      packet.extract(hdr.ipv4);
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
   //clear Ethernet
   action invalid_ethernet() {
      hdr.ethernet.setInvalid();
   }

   //add Ethernet
   action update_ethernet(egressSpec_t port, macAddr_t srcAddr, macAddr_t dstAddr) {
      standard_metadata.egress_spec = port;
      //update Ethernet
      hdr.ethernet.setValid();
      hdr.ethernet.srcAddr   = srcAddr;
      hdr.ethernet.dstAddr   = dstAddr;
      hdr.ethernet.etherType = 0x800; //IPv4
      
      //hdr.ipv4.ttl = hdr.ipv4.ttl - 1;

   }

   table port_forward {
      key = {
         standard_metadata.ingress_port: exact;
      }
      actions = {
         update_ethernet;
         invalid_ethernet;
         NoAction;
      }
      size = 256;
      default_action = invalid_ethernet();
   }

   apply {
      log_msg("new packet comming from port = {}", {standard_metadata.ingress_port});

      if ( standard_metadata.ingress_port ==  1 ){
        standard_metadata.egress_spec = 2;
      } else {
        standard_metadata.egress_spec = 1;
        log_msg("mac_src: {}, mac_dst: {}", {hdr.ethernet.srcAddr, hdr.ethernet.dstAddr});
        //drop broadcast
        if(hdr.ethernet.dstAddr != 1 && hdr.ethernet.dstAddr != 2 ){
          log_msg(" dopped packet");
          mark_to_drop(standard_metadata);
          return;
        }
      }

      //port_forward.apply();
   }
}

/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

control MyEgress(inout headers hdr,
      inout metadata meta,
      inout standard_metadata_t standard_metadata) {
   apply {

      if ( standard_metadata.egress_port ==  2 ){
        hdr.ethernet.setValid();
        hdr.ethernet.srcAddr = 1;
        hdr.ethernet.dstAddr = 2;
        hdr.ethernet.etherType = 0x800; //IPv4
      } else {
        hdr.ethernet.setInvalid();
      }

      //hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
      //log_msg( "ingress port: {}, egress port: {}", {standard_metadata.ingress_port, standard_metadata.egress_port});
      //log_msg("ip_dst: {}", {hdr.ipv4.dstAddr} );
      
   }
}

/*************************************************************************
 *************   C H E C K S U M    C O M P U T A T I O N   **************
 *************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
   apply {
      update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.dscp,
            hdr.ipv4.ecn,
            hdr.ipv4.totalLen,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.fragOffset,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.srcAddr,
            hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
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
