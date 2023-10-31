/* -*- P4_16 -*- */

//  Pour compiler : p4c --target bmv2 --arch v1model L4S_v3.p4

// Pour lancer : //sudo ../behavioral-model/targets/simple_switch/simple_switch --device-id 1 -i 1@s1_server -i 2@s1_client --queue 2 --thrift-port 9090 --ll_queue 64 --BE_queue  128 L4S_v3.json


//298  ethtool -k ens3
//299  ethtool -k ens3 | grep check
//300  ethtool -K ens3 rx on tx off
//301  sudo ethtool -K ens3 rx on tx off
#include <core.p4>
#include <v1model.p4>

#include "int.p4"

/************HEADERS**********/

const bit<16> TYPE_PROBE = 0x801;
const bit<16> TYPE_ARP   = 0x0806;

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<48> time_t;
#define MAX_HOPS 10
#define MAX_PORTS 8


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

header probe_t{
   bit<32> delay;
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

struct feedback_s{

}

struct metadata {
   bit<7> swid;
   bit<5> test;
   bit <8> queue_id_test;
   bit<8> default_port;
   bit<16> hash_index;
   bit<48> time_hash;
   bit<4> priority_flow;
   bit<32> bid;
   bit<32> counter; 
   bit<32> count;
   bit<32> proba_L4S_Nat;
   bit<32> proba_L4S;
   bit<32> last_probability;
   bit<32> proba_L4Sa;
   bit<32> last_probabilitya;
   bit<34> classic_proba;
   bit<1> proba_aqm;
   bit<7>  priority_weight;
   bit<7> queue_depth;
   feedback_s feedback;
   bit<32> marked_LL; 
   bit<32> marked_LL_max; 
   bit<32> marked_LL2; 
   bit<32> marked_LL_max2; 
   bit<32> pkt;
   bit<32> pkt2;
   @field_list(0)
   bit<32> marked_BE;
   @field_list(0) 
   bit<32> dropped_BE;
   @field_list(0)
   bool is_ll_traffic; //LL or BE
   //HN: add INT
   // By giving a field list index 0 as a parameter to
   // clone_preserving_field_list, all user-defined metadata
   // fields with annotation @field_list(0) will have their
   // values preserved from the packet being processed now, to
   // the resubmitted packet that will be processed by the
   // ingress control block in the near future.
   @field_list(0)
   int_metadata _int;
}

struct headers {
   ethernet_t  ethernet;
   ipv4_t      ipv4;
   tcp_t       tcp;
   udp_t       udp;
   probe_t     probe;
   
   //HN: add parsing TCP option
   tcp_option_t[MAX_TCP_OPTION_WORD] tcp_opt;

   //HN: add INT
   int_headers _int;
}

/* CONSTANTS */

#define K_Factor 2
const bit<32> MAX_RND = 0xFFFFFFFF;
// BM const bit<32> OVERLOAD = 0xCCCCCCCC;
const bit<32> OVERLOAD = 0x7FFFFFFF;    // MAX_RND/F_Factor; puisque last_probability = p' et non p_CL
#define WRITE_REG(r, v) r.write((bit<32>)0, v);
#define READ_REG(r, v) r.read(v,(bit<32>)0);
#define CAP(c, v, a, t){ if (v > c) a = c; else a = (t)v; };
#define max(a,b){if(a>b) a = a;else a = b;};
typedef int<32> alpha_t;
typedef int<32> beta_t;
typedef int<32> delay_t;
typedef bit<5>  interval_t;


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
               out headers hdr,
               inout metadata meta,
               inout standard_metadata_t standard_metadata) {
   //HN: local variable to count TCP options in number of words
   bit<4> tcp_opt_cnt = 0;

   state start {
      log_msg("\n\n ================================ new packet ===================== ");
      transition parse_ethernet;
   }

   state parse_ethernet{
      packet.extract(hdr.ethernet);
      transition select(hdr.ethernet.etherType){
          0x800      : parse_ipv4;
          TYPE_PROBE : parse_probe;

      }
   }

   state parse_probe{
      packet.extract(hdr.probe);
      transition parse_ipv4;
   }

   state parse_ipv4{
      packet.extract(hdr.ipv4);

      ///L4S services
      //if(hdr.ipv4.diffserv%2==1){
      //if( true )
      //if( hdr.ipv4.ecn ==  3)
      // #define PICOQUIC_ECN_ECT_0 0x02  <-- classic ECN
      // #define PICOQUIC_ECN_ECT_1 0x01  <-- L4S ECN
      // #define PICOQUIC_ECN_CE 0x03     <-- congestion
      if( hdr.ipv4.ecn % 2 ==  1 )
      //10.0.0.11 or 10.0.1.11
      //if( hdr.ipv4.srcAddr ==  0x0a00000b || hdr.ipv4.srcAddr ==  0x0a00010b )
      //if( hdr.ipv4.identification ==  0)
         meta.is_ll_traffic = true;
      else
         meta.is_ll_traffic = false;

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
      //exclude 5 words ( = 20 bytes) of the fixed tcp header that is defined in tcp_t
      if( tcp_opt_cnt > 5 )
         tcp_opt_cnt = tcp_opt_cnt - 5;
      else
         tcp_opt_cnt = 0;

      transition select( tcp_opt_cnt ){
         0       : parse_int_over_tcp;
         default : parse_tcp_option;
      }
   }

   //HN
   state parse_int_over_tcp {
      int_parser.apply( packet, hdr.ipv4.dscp, hdr.ipv4.srcAddr, hdr.tcp.srcPort, hdr.ipv4.dstAddr, hdr.tcp.dstPort, hdr._int, meta._int, standard_metadata, meta.is_ll_traffic );
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

      //HN: parse INT
      int_parser.apply( packet, hdr.ipv4.dscp, hdr.ipv4.srcAddr, hdr.udp.srcPort, hdr.ipv4.dstAddr, hdr.udp.dstPort, hdr._int, meta._int, standard_metadata, meta.is_ll_traffic  );
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
      //HN: here the packet is dropped because no route is found
      //  => do not cause by L4S
      //  => ignore L4S stats
      mark_to_drop(standard_metadata);
   }

   // Simple forward of IPV4
   action ipv4_forward(macAddr_t srcAddr, macAddr_t dstAddr, egressSpec_t port) {
      standard_metadata.egress_spec = port;
      //HN
      hdr.ethernet.srcAddr = srcAddr;
      hdr.ethernet.dstAddr = dstAddr;
      //HN
      hdr.ipv4.ttl = hdr.ipv4.ttl-1;
      meta.queue_id_test = standard_metadata.qid;
   }

   table ipv4_lpm {
      key = {
         hdr.ipv4.dstAddr : exact;
      }
      actions = {
         drop;
         ipv4_forward;
      }
      size = 256;
      default_action = drop;
   }

   action set_mcast_grp(bit<16> mcast_grp){
      standard_metadata.mcast_grp = mcast_grp;
   }
   table select_mcast_grp{
      key = {
         standard_metadata.ingress_port : exact;
      }
      actions = {
         NoAction;
         set_mcast_grp;
      }
   }

   apply {
      // standard_metadata.probability = 2;
      // bit<33>rnd;
      if(hdr.ethernet.etherType == TYPE_ARP){
         select_mcast_grp.apply();
      }
      else{
         if(hdr.ipv4.isValid()){
            ipv4_lpm.apply();
            //L4S Traffic
            //if(hdr.ipv4.diffserv%2 =  = 1){
            //if(hdr.ipv4.ecn%2 ==  1){
            //if(hdr.ipv4.ecn !=  0 ){//&& hdr.ipv4.dstAddr ==  0xC0A86DD8){
            //if(hdr.ipv4.ecn ==  2){
            if( meta.is_ll_traffic ){
               //HN - 21/Mar/2023: somehow this modification conflicts with clone_preserving_field_list
               // this modification prevents clone_preserving_field_list from working correctly: the clone function is blocked
               standard_metadata.priority = 1;
            }
            //Classic Trafic
            else{
               standard_metadata.priority = 0;
            }

            //HN: INT work over IP so we put here its ingress
            //int_ingress.apply( hdr._int, meta._int, standard_metadata );
         }
      }
   }
}

control debug_tables(in standard_metadata_t stdmeta, in metadata meta) {
   table dbg_table {
      key = {
         //stdmeta.ingress_port:exact;
         //stdmeta.egress_spec:exact;
         //stdmeta.egress_port:exact;
         stdmeta.deq_timedelta: exact;
         meta.marked_LL       : exact;
         meta.marked_LL_max   : exact;
         meta.marked_BE       : exact;
         meta.dropped_BE      : exact;
      }
      actions = { NoAction; }
      const default_action = NoAction();
   }
   apply {
      dbg_table.apply();
   }
}


/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

   register<bit<48>>(256) r_update_time;  // timestamp of previous PI calculation
   register<int<32>>(256) r_queue_delay;  // queue delay at previous PI calculation
   register<bit<32>>(256) r_PI2_probability;
   register<bit<64>>(256) r_L4S_Proba;
   alpha_t alpha;
   beta_t beta;
   delay_t target;
   //interval_t intervala = 10;
   interval_t interval = 14;     // PI update interval is 2^x us, x = 14  => 16384 us ~ =  16 msec
   bit<32> last_probability;
   bit<32> maxTH;
   bit<32> minTH;
   bit<8> debit;
   bit<32> MTU;
   bit<32> floor;
   bit<8> range_L4S;
   bit<64> proba_L4S;
   bit<5> protection;
   // BM bit<32> t_update;
   bit<8> t_update;
   bit<64> proba_L4Sa;
   bit<32> t_updatea;

   debug_tables() debug_tables_egress_end;

   action drop_l4s() {
      mark_to_drop(standard_metadata);
      int_l4s_drop( meta._int);
      //meta._int.l4s.drop = 1;
   }
   action mark_l4s(){
      hdr.ipv4.ecn = 3;
      int_l4s_mark( meta._int );
      //meta._int.l4s.mark = 1;
   }

   // Set AQM PI2 param, for example : table_add select_PI2_param set_PI2_param  => 1342 13421 15000 16 (target in microseconds, t_update in ms)
   // Set AQM PI2 param, for example : table_add select_PI2_param set_PI2_param  => 0.25 3 25000 25 (target in microseconds, t_update in ms)   si RTT max de 100ms entre switch-server
   // Set AQM PI2 param, for example : table_add select_PI2_param set_PI2_param  => 1,5 7,5 25000 25 (target in microseconds, t_update in ms)   si RTT max de 40ms entre switch-server
   // Set AQM PI2 param, for example : table_add select_PI2_param set_PI2_param  => 1 6 25000 25 (target in microseconds, t_update in ms)
   // Pour RTT_Max = 100ms et RTT_typ = 25ms
   // alpha = 0.1 * Tupdate / RTT_max^2 = 0,25
   // beta =  0.3 / RTT_max =  3
   // target = RTT_typ = 5ms
   // t_update = min(RTT_typ, RTT_max/3) = 15ms


    // alpha and beta needs to be multiplied by (2^32-1)/1000000 = 4295 which is due to random value goes to 2^32
    // alpha = 0,3125  => 1342 and beta = 3,125  => 13422
    // delay target is in us = 20000  => 20 msec
    // PI update interval is 2^x us, x = 15  => 32768 us ~ =  33 msec
    // PI update interval is 2^x us, x = 14  => 16384 us ~ =  16 msec

    // BM action set_PI2_param(int<32>alpha_param, int<32> beta_param, int<32> target_param,bit<32> t_update_param){
    action set_PI2_param(int<32>alpha_param, int<32> beta_param, int<32> target_param,bit<8> t_update_param){
        alpha = alpha_param;
        beta = beta_param;
        target = target_param;
        t_update = t_update_param;
    }

    table select_PI2_param{
        actions = {
            set_PI2_param;
        }
    }

   //Set L4S param, for example : table_add select_L4S_param set_L4S_param  => 3000 1000 0 1500 21 (Max and Min in microseconds, 0 debit (no change needed) and 21 because we have Max-Min = 2000, so 2000<<21 ==  MaxRnd)
   // 32 bits à 111111...11 décaler de 21 à droite  => 2047 (# 3000-1000)
   // Il faut calculer cette valeur de décalage quand on configure les seuils max et min de L4S :
   // Par ex : 5000 max et 500 min   => 4500   => décalage de 20
   // Si ecart en max et min = 8000  => decalage de 22 : range = 19
   // Si ecart en max et min = 4000  => decalage de 22 : range = 20
   // Si ecart en max et min = 2000  => decalage de 22 : range = 21
   // Si ecart en max et min = 1000  => decalage de 22 : range = 22
   // Si ecart en max et min = 500   => decalage de 22 : range = 23

   /* Bien specifier les valeurs MaxTH minTH et range_L4S  */

   action set_L4S_param(bit<32>MAX_param, bit<32> MIN_param, bit<8> debit_param_min, bit<32> MTU_param,bit<8> range_param){
      maxTH = MAX_param;
      minTH = MIN_param;
      range_L4S = range_param;
      debit = debit_param_min;
      MTU = MTU_param;
/*  Calcul dynamique pour floor et minTH non fait, car débit pas calcule en temps reel : valeurs pas utilisés dans le calcul de l'AQM L4S*/
      floor = (2*MTU);   // floor = (2*MTU)/min_link_rate   : debit = debit_param_min = min_link_rate = 1 Mbps
   }

   table select_L4S_param{
      actions = {
         set_L4S_param;
      }
   }
   action set_Classic_Protection(bit<5> protection_param){
      protection = protection_param;
   }

   table select_Classic_Protection{
      actions = {
         set_Classic_Protection;
      }
   }

   apply {
      //HN: initialize variables to avoid warning
      protection = 0;
      maxTH = 0;
      minTH = 0;
      range_L4S = 0;
      t_updatea = 0;
      beta = 0;
      alpha = 0;
      target = 0;
      t_update = 0;

/*   if ( standard_metadata.ingress_port ==  1 ) standard_metadata.egress_spec = 2;
        else standard_metadata.egress_spec = 1;

*/


      int_egress.apply( hdr._int, meta._int, standard_metadata );
      if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_EGRESS_CLONE) {
         //reset priority to copy to INT
         //standard_metadata.priority = 0;
         hdr.ipv4.dscp = INT_IPv4_DSCP;
         //hdr.ipv4.dstAddr =  0x0a001E02; //10.0.30.2 IP of INT collector
         hdr.ipv4.totalLen = hdr.ipv4.totalLen + (bit<16>)meta._int.insert_byte_cnt;
         return;
      }

      //Get the classic protection from User
      select_Classic_Protection.apply();
      // By default,  = 1 (for ARP packets or ICMP for example)
      standard_metadata.probability = 1;

      //if ( standard_metadata.egress_port ==  2 ) 
      // egress_port == 2: server
      // egress_port == 1: client
      // we are interested in the direction from server --> client
      if ( standard_metadata.egress_port ==  1 )
      {

         // Random variable to use with the probability
         bit<32>rnd;
         random( rnd, 0, MAX_RND );
         //Read last proba, needed in bith L4S and Classic packet computation
         READ_REG( r_PI2_probability, last_probability );


         //L4S services
         //if(hdr.ipv4.diffserv%2 =  = 1){
         //if(hdr.ipv4.ecn%2 ==  1){
         //if(hdr.ipv4.ecn ==  2){
         //if( hdr.ipv4.srcAddr ==  0x0A00000B){
         if( meta.is_ll_traffic ){

            standard_metadata.probability = 16 - protection;

            //Apply parameters dynamically
            select_L4S_param.apply();
            //HN print parameters
            log_msg("PI2 params: max={}, min={}, range={}, debit={}, MTU={}", {maxTH, minTH, range_L4S, debit, MTU});
            // No overload, DUAL_Q_COUPLED standard
            // Non fait, car débit pas calcule en temps -reel : donc definit debit min 1 Mbit/s  => floor = 3ms
            // if(debit!= 0){
            //   floor = (2*MTU)>>debit; //debit ==> (8/(Mb/s))*1000000 (donne le décalage binaire à faire ) Par exemple, 3000<<1 ==  6000. Donc, pour 4Mb/s, on décalle de 1 pour un MTU à 3000. Débit != 0 pour réglage
            //   if(floor>minTH) 
            //     minTH = floor;
            // }
            // if((maxTH+range)<minTH)
            //   maxTH = (minTH+range);  // Fait par param aevc decalage

            // Calcul proba L4S (laqm)
            meta.proba_L4S_Nat = 0;
            if( standard_metadata.deq_timedelta > maxTH )
               meta.proba_L4S_Nat = MAX_RND;
            else if( standard_metadata.deq_timedelta > minTH )
               meta.proba_L4S_Nat = (standard_metadata.deq_timedelta - minTH) << range_L4S; //(MAX_RND)/(MAX_TH-MIN_TH) range pour mettre la proba sur 32bit, à passer en param par user et en puissance de 2
            else 
               meta.proba_L4S_Nat = 0;

            // K_FACTOR coupled queue
            max( meta.proba_L4S_Nat, K_Factor*last_probability );

            //OVERLOAD of classic queue, we can imagine also change the protection param here
            if( last_probability < OVERLOAD ){
               READ_REG( r_L4S_Proba, proba_L4S );
               proba_L4S = proba_L4S + (bit<64>)meta.proba_L4S_Nat;

               if( proba_L4S > (bit<64>)MAX_RND ){
                  //meta.marked_LL = 1;
                  mark_l4s();
                  proba_L4S = proba_L4S-(bit<64>)MAX_RND;

                  //HN: remember mark-probability
                  meta._int.mark_probability = MAX_RND;
               } else
                  meta._int.mark_probability = (bit<32>)proba_L4S;
                  
               WRITE_REG( r_L4S_Proba, proba_L4S );
               //end of recur() from IETF draft
            }
         } else {
            //Classic Service
            //if(hdr.ipv4.diffserv%2 =  = 0){
            //if(hdr.ipv4.ecn%2 ==  0){
            //if(hdr.ipv4.ecn !=  2 ){//&& hdr.ipv4.srcAddr ==  0xC0A86D73){
            //if( hdr.ipv4.srcAddr ==  0x0A00000C){

            // Calcul PI2 à faire seulement si Temps depuis précedent > T_update

            //Apply parameters dynamically
            select_PI2_param.apply();
            standard_metadata.probability = protection;

            bit<32>rnd_2;
            random(rnd_2,0,MAX_RND);
            bit<48> last_update_time = 0;
            int<32> last_queue_delay;
            int<32> delta;

            READ_REG(r_update_time, last_update_time);  // read r_update_time -> timestamp of last prob update
            READ_REG(r_queue_delay, last_queue_delay);  // read q_delay during previous update time

            // initialization - no previous update time
            if(last_update_time == 0)
               last_update_time = standard_metadata.egress_global_timestamp;
            //find how many time laps - divide by 2^t_update = 2^15 = 32768 ms
            //find how many time laps - divide by 2^t_update = 2^14 = 16384 ms
            //Update_laps in ms, rendu configurable par table
            bit<32> update_laps = (bit<32>) ((standard_metadata.egress_global_timestamp - last_update_time) >> t_update );


            if(update_laps >=  1){

               if(update_laps >=  2000)
                  update_laps = 2000;   // limit to max useful number = max queue_del / min target (1ms)

               int<32> prev_queue_delay = last_queue_delay;   // preserve previous queue delay
               CAP(1000000, standard_metadata.deq_timedelta, last_queue_delay, int<32>); // update and cap queueing delay to 1s
               //#define CAP(c, v, a, t){ if (v > c) a = c; else a = (t)v; };

               // calculate change in probability
               delta = (last_queue_delay -  target) * alpha + (last_queue_delay - prev_queue_delay) * beta;

               bit<33> new_probability = (bit<33>) last_probability; // add one bit to detect under- and overflows
               new_probability = (bit<33>) ((int<33>) new_probability + (int<33>) delta);  // delta needs sign preservation
               if (new_probability > (bit<33>)MAX_RND) { // check for under- and overflows
                  if (delta > 0)
                     last_probability = MAX_RND;
                  else
                     last_probability = 0;
               } else 
                  last_probability = (bit<32>) new_probability;

               last_update_time = standard_metadata.egress_global_timestamp; // set last_update_time

               //update registers
               WRITE_REG(r_PI2_probability, last_probability); // store new drop probability
               WRITE_REG(r_queue_delay, last_queue_delay); // store delay
            }

            // store last_update_time
            WRITE_REG(r_update_time, last_update_time);

            if(last_probability > rnd && last_probability > rnd_2){  // pour remplacer le proba au carré
               //if((hdr.ipv4.diffserv&(bit<8>)2) ==  2){
               if(hdr.ipv4.ecn ==  2){
                  // Le test si proba au carré > proba_max n'est pas fait
                  //meta.marked_BE = 1;
                  mark_l4s();
                  //drop();
               } else {
                  //meta.dropped_BE = 1;
                  drop_l4s();
               }
            }
            //HN: remember mark-probability
            meta._int.mark_probability = (bit<32>)last_probability;

            //debug_tables_egress_end.apply(standard_metadata, meta);
         }
      }


      //HN: do INT here
      //update IP when INT is enable on this node.
      //We ignore updating the length of TCP or UDP for now
      // becasue this length will be restored to the original one
      // when the packet goes out of the sink node.
      // Consequently we can ignore also their checksum for now.
      //if( meta._int.int_node & INT_NODE_SINK !=  0 ){
      //   clone3<metadata>(CloneType.E2E, REPORT_MIRROR_SESSION_ID, meta)
      //}
      //int_egress.apply( hdr._int, meta._int, standard_metadata );
      /*
      if( meta._int.int_node & INT_NODE_SOURCE !=  0 ){
         //modify dscp to mark the presence of INT in this packet
         hdr.ipv4.dscp = INT_IPv4_DSCP;
         //add size of INT headers
         hdr.ipv4.totalLen = hdr.ipv4.totalLen + INT_ALL_HEADER_LEN_BYTES;
      } 
      if( meta._int.int_node & INT_NODE_SINK !=  0 ){
         //restor original dscp
         hdr.ipv4.dscp = hdr._int.shim.dscp;
         //remove INT headers and its data
         bit<16> len_bytes = ((bit<16>)hdr._int.shim.len) << 2;
         hdr.ipv4.totalLen = hdr.ipv4.totalLen - len_bytes;
      }
      if( meta._int.int_node & INT_NODE_TRANSIT !=  0 ){
         hdr.ipv4.totalLen = hdr.ipv4.totalLen + (bit<16>)meta._int.insert_byte_cnt;
      }
      */
      //end INT
   }//end of apply
}




/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
   apply {
      update_checksum(
         hdr.ipv4.isValid(),
         {
            hdr.ipv4.version,
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
            hdr.ipv4.dstAddr
         },
         hdr.ipv4.hdrChecksum,
         HashAlgorithm.csum16
      );
   }
}



/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
   apply {
      packet.emit(hdr.ethernet);
      packet.emit(hdr.probe);
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

//switch architecture
V1Switch(
   MyParser(),
   MyVerifyChecksum(),
   MyIngress(),
   MyEgress(),
   MyComputeChecksum(),
   MyDeparser()
) main;
