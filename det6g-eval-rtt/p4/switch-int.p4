/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "int.p4"

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

header tcp_t{
   bit<16> srcPort;
   bit<16> dstPort;
   bit<32> seqNo;
   bit<32> ackNo;
   bit<4>  dataOffset;
   bit<4>  res;
   bit<1>  cwr;
   bit<1>  ece;
   bit<1>  urg;
   bit<1>  ack;
   bit<1>  psh;
   bit<1>  rst;
   bit<1>  syn;
   bit<1>  fin;
   bit<16> window;
   bit<16> checksum;
   bit<16> urgentPtr;
}


#define MAX_TCP_OPTION_WORD 10
header tcp_option_t{
   bit<32> data;
}

header udp_t {
   bit<16> srcPort;
   bit<16> dstPort;
   bit<16> length;
   bit<16> checksum;
}

struct metadata {
   /* empty */
   int_metadata _int;
}

struct headers {
   ethernet_t  ethernet;
   ipv4_t      ipv4;
   udp_t       udp;
   tcp_t       tcp;

   tcp_option_t[MAX_TCP_OPTION_WORD] tcp_opt;
   int_headers _int;
}

/*************************************************************************
 *********************** P A R S E R  ***********************************
 *************************************************************************/

parser MyParser(packet_in packet,
      out headers hdr,
      inout metadata meta,
      inout standard_metadata_t standard_metadata) {

      //HN: local variable to count TCP options in number of words
   bit<4> tcp_opt_cnt = 0;

   //traffic can start with IP or Ethernet protocol
   // - ipv4 for the NICs uesimtun0 (UE) or ogstun (UPF)
   // - ethernet for the NICs which communicate with our client or server programs 
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
      transition select(hdr.ipv4.protocol){
         0x006  : parse_tcp;
         0x011  : parse_udp;
         default: accept;
      }
   }

   state parse_tcp {
      packet.extract(hdr.tcp);

       //HN: jump over TCP options
      tcp_opt_cnt = hdr.tcp.dataOffset;
      //exclude 5 words (=20 bytes) of the fixed tcp header that is defined in tcp_t
      if( tcp_opt_cnt > 5 )
         tcp_opt_cnt = tcp_opt_cnt - 5;
      else
         tcp_opt_cnt = 0;
      log_msg("====TCP data offset = {}", {tcp_opt_cnt});
      transition select( tcp_opt_cnt ){
         0       : parse_int_over_tcp;
         default : parse_tcp_option;
      }
   }

   state parse_int_over_tcp {
      int_parser.apply( packet, hdr.ipv4.dscp, hdr.ipv4.srcAddr, hdr.tcp.srcPort, hdr.ipv4.dstAddr, hdr.tcp.dstPort, hdr._int, meta._int, standard_metadata, false );
      transition accept;
   }

   state parse_tcp_option {
      packet.extract( hdr.tcp_opt.next );
      tcp_opt_cnt = tcp_opt_cnt - 1;
      transition select( tcp_opt_cnt ){
         0      : parse_int_over_tcp;
         default: parse_tcp_option;
      }
   }


   state parse_udp {
      packet.extract(hdr.udp);
      int_parser.apply( packet, hdr.ipv4.dscp, hdr.ipv4.srcAddr, hdr.udp.srcPort, hdr.ipv4.dstAddr, hdr.udp.dstPort, hdr._int, meta._int, standard_metadata, false );
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

   action source(bit<8> val){
      mark_to_drop(standard_metadata);
      log_msg("Blocklist. Drop packet coming from  source IP = {}", { hdr.ipv4.srcAddr });
   }
   table tb_blocklist {
      key = {
         hdr.ipv4.srcAddr : exact;
      }
      actions = {
         NoAction;
         source;
      }
      size = 256;
      default_action = NoAction;
   }
   
   apply {
      if ( standard_metadata.ingress_port ==  1 ){
        standard_metadata.egress_spec = 2;
      } else {
        standard_metadata.egress_spec = 1;
        //log_msg("mac_src: {}, mac_dst: {}", {hdr.ethernet.srcAddr, hdr.ethernet.dstAddr});
        //drop broadcast
        if(hdr.ethernet.dstAddr != 1 && hdr.ethernet.dstAddr != 2 ){
          // log_msg(" ==> dopped broadcast packet");
          mark_to_drop(standard_metadata);
          return;
        }
      }
      
      log_msg("new packet comming from port = {}", {standard_metadata.ingress_port});
      log_msg("ip_src: {}, ip_dst: {}", {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr} );
      
      //somehow UERANSIM sends out RST packets
      // these packets cause our client & server reseting their connection
      // => drop these packet
      if( hdr.tcp.rst == 1 && hdr.ipv4.srcAddr == 170721290 ){
         log_msg( " ==> drop reset");
         mark_to_drop(standard_metadata);
      }

      if (hdr.ipv4.isValid()) {
         //check if the IP source is in block list
         if( tb_blocklist.apply().hit ){
            //drop the packet
            //source(1);
            return;
         }
         //INT work over IP so we put here its ingress
         int_ingress.apply( hdr._int, meta._int, standard_metadata );
      }
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
        hdr.ethernet.srcAddr = 1; //src & dst MAC are fixed
        hdr.ethernet.dstAddr = 2;
        hdr.ethernet.etherType = 0x800; //IPv4
        //hdr.ipv4.dstAddr = 170721290;
      } else {
         //we keep Ethernet when packet is cloned to send to INT-collector
         if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_NORMAL){
           log_msg("remove Ethernet");
           //hdr.ipv4.srcAddr = 170721290;
           hdr.ethernet.setInvalid();
         } else 
           hdr.ethernet.setValid();
      }



      int_egress.apply( hdr._int, meta._int, standard_metadata );
      /*
      if( meta._int.int_node & INT_NODE_SOURCE != 0 ){
         //modify dscp to mark the presence of INT in this packet
         hdr.ipv4.dscp = INT_IPv4_DSCP;
         //add size of INT headers
         hdr.ipv4.totalLen = hdr.ipv4.totalLen + INT_ALL_HEADER_LEN_BYTES;
      } 
      if( meta._int.int_node & INT_NODE_SINK != 0 ){
         //restor original dscp
         hdr.ipv4.dscp = hdr._int.shim.dscp;
         //remove INT headers and its data
         bit<16> len_bytes = ((bit<16>)hdr._int.shim.len) << 2;
         hdr.ipv4.totalLen = hdr.ipv4.totalLen - len_bytes;
      }
      if( meta._int.int_node & INT_NODE_TRANSIT != 0 ){
         hdr.ipv4.totalLen = hdr.ipv4.totalLen + (bit<16>)meta._int.insert_byte_cnt;
      }
      */
      if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_EGRESS_CLONE) {
         //reset priority to copy to INT
         //standard_metadata.priority = 0;
         hdr.ipv4.dscp = INT_IPv4_DSCP;
         //hdr.ipv4.dstAddr =  0x0a001E02; //10.0.30.2 IP of INT collector
         hdr.ipv4.totalLen = hdr.ipv4.totalLen + (bit<16>)meta._int.insert_byte_cnt;
         return;
      }

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
      packet.emit(hdr.tcp);
      packet.emit(hdr.udp);

      packet.emit(hdr.tcp_opt);
      int_deparser.apply( packet, hdr._int );
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
