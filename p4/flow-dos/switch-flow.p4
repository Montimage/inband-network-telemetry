/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "int.p4"

/*
 * This P4 code implements a simple switch to get the interval between the first and latest packets for each source IP.
 * The counter of an IP will be reported via in-band network telemetry 
 *  not for every single packet, but each 128 packets. 
 *  After being reported, the counter is reseted to 0.
 *
 * The implementation uses a simple bloom filter to check 
 *  if a comming packet is a part of an already initialized counter.
 *
 * Created on: Nov 07, 2023
 *			by: Huu Nghia
 */

/*************************************************************************
 *********************** H E A D E R S  ***********************************
 *************************************************************************/

// number of counters
#define BLOOM_FILTER_ENTRIES 4096
// bit size of a counter: 32bit
#define TIMESTAMP_BIT_WIDTH 32
// count maxi 255 packets
#define COUNTER_BIT_WIDTH    8
//frequency of report: a report each 128 packets
#define REPORT_FREQ 128

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
	macAddr_t dstAddr;
	macAddr_t srcAddr;
	bit<16>	etherType;
}

header ipv4_t {
	bit<4>	 version;
	bit<4>	 ihl;
	bit<6>	 dscp;
	bit<2>	 ecn;
	bit<16>	totalLen;
	bit<16>	identification;
	bit<3>	 flags;
	bit<13>	fragOffset;
	bit<8>	 ttl;
	bit<8>	 protocol;
	bit<16>	hdrChecksum;
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
	ipv4_t		ipv4;
	udp_t		 udp;
	tcp_t		 tcp;

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

	//local variable to count TCP options in number of words
	bit<4> tcp_opt_cnt = 0;

	state start {
		transition parse_ethernet;
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
			0		 : parse_int_over_tcp;
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
			0		: parse_int_over_tcp;
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
 ************	C H E C K S U M	 V E R I F I C A T I O N	*************
 *************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
	apply {  }
}


/*************************************************************************
 **************  I N G R E S S	P R O C E S S I N G	*******************
 *************************************************************************/

control MyIngress(inout headers hdr,
		inout metadata meta,
		inout standard_metadata_t standard_metadata) {
		
	register<bit<TIMESTAMP_BIT_WIDTH>>(BLOOM_FILTER_ENTRIES) timestamp_filter;
	register<bit<COUNTER_BIT_WIDTH>>(BLOOM_FILTER_ENTRIES)   counter_filter;
	bit<COUNTER_BIT_WIDTH> counter_val;
	bit<TIMESTAMP_BIT_WIDTH> current_ts_ms;
	bit<TIMESTAMP_BIT_WIDTH> ts_val;
	bit<32> counter_pos;
	bit<16> pps;
	

	//get register position of corresponding counter
	action compute_hash(ip4Addr_t srcIp){
		hash( counter_pos, HashAlgorithm.crc16, (bit<16>)0, {srcIp}, (bit<32>)BLOOM_FILTER_ENTRIES);
	}

	action drop() {
		mark_to_drop(standard_metadata);
	}

	action update_mac_address(macAddr_t srcAddr, macAddr_t dstAddr, egressSpec_t port) {
		standard_metadata.egress_spec = port;
		hdr.ethernet.srcAddr = srcAddr;
		hdr.ethernet.dstAddr = dstAddr;
		hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
	}

	/* table contain dst IP to be forwarded */
	table ipv4_forward {
		key = {
			hdr.ipv4.dstAddr: exact;
		}
		actions = {
			update_mac_address;
			drop;
			NoAction;
		}
		size = 256;
		default_action = drop();
	}
	
	/* table contain source IP to be blocked*/
	table ipv4_block {
		key = {
			hdr.ipv4.srcAddr: exact;
		}
		actions = {
			drop;
			NoAction;
		}
		size = 256;
		default_action = drop();
	}

	apply {
		// work only on valid IPv4 packets
		if (hdr.ipv4.isValid()) {
			// source IP is in blocked list
			if( ipv4_block.apply().hit )
				// drop the packet
				drop();
			else {
				ipv4_forward.apply();
				
				//get number of packets comming from srcAddr
				compute_hash( hdr.ipv4.srcAddr );
				
				counter_filter.read(counter_val, counter_pos);
				// increase number of packets comming from this source IP
				counter_filter.write(counter_pos, counter_val+1);
				
				// ingress timestamp of the packet in millisecond
				current_ts_ms = (bit<TIMESTAMP_BIT_WIDTH>) (standard_metadata.ingress_global_timestamp / 1000); //ingress_tstamp is in microsecond
				
				//for the first time: remember its timestamp
				if( counter_val == 0 )
					timestamp_filter.write(counter_pos, current_ts_ms);
				else if( counter_val >= REPORT_FREQ ){
					//reset the counter
					counter_filter.write(counter_pos, 0);
					
					// get timestamp of the first packet
					timestamp_filter.read(ts_val, counter_pos);
					//get interval
					ts_val = (current_ts_ms - ts_val);
					
					//calculate throughput packet-per-second
					// bit<16> : support max 65526 pps
					pps = (bit<16>)(REPORT_FREQ / ts_val / 1000);
					
					//rember this value tobe able to embed it into INT
					int_mark_packets( meta._int, pps);
					//INT work over IP so we put here its ingress
					int_ingress.apply( hdr._int, meta._int, standard_metadata );
				}
				
			}
		}
	}
}

/*************************************************************************
 ****************  E G R E S S	P R O C E S S I N G	*******************
 *************************************************************************/

control MyEgress(inout headers hdr,
		inout metadata meta,
		inout standard_metadata_t standard_metadata) {
	apply {

		//clone3<metadata>(CloneType.E2E, REPORT_MIRROR_SESSION_ID, meta);
		//clone(CloneType.E2E, REPORT_MIRROR_SESSION_ID);
		
		int_egress.apply( hdr._int, meta._int, standard_metadata );
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

	}
}

/*************************************************************************
 *************	C H E C K S U M	 C O M P U T A T I O N	**************
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
