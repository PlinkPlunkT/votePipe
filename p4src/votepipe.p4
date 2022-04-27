/* -*- P4_16 -*- */
/* Source code of VotePipe */

#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <tna2.p4>
#else
#include <tna.p4>
#endif

#include "common/headers.p4"
#include "common/util.p4"

/****** C O N S T A N T S A N D T Y P E S ********/

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
// 寄存器数组大小
const bit<10> register_array_size = 1 << 10;
// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
typedef bit<104> flow_ID_t;
typedef bit<16> register_value_t;

/****** H E A D E R D E F I N I T I O N S ********/
// 见headers.p4

/****** I N G R E S S P I P E L I N E ********/

struct metadata_t {
    // 是否携带了上个阶段的信息
    boolean carried;
    // index值
    bit<10> arrayIndex;
    // 携带的key
    flow_ID_t keyCarried;
    // 携带的count
    register_value_t countCarried;
}

// ---------------------------------------------------------------------------
// Ingress Parser: 对头部进行解析
// ---------------------------------------------------------------------------
parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    TofinoIngressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, ig_intr_md);
        transition parse_ethernet;
    }

    // 解析以太网头
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default : accept;
        }
    }

    // 解析ipv4头
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP : parse_tcp;
            IP_PROTOCOLS_UDP : parse_udp;
            default : accept;
        }
    }

    // 解析tcp头
    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }

    // 解析udp头
    state parse_udp {
        pkt.extract(hdr.udp);
        transition accetp;
    }
}

// ---------------------------------------------------------------------------
// Ingress Control: 逻辑实现
// ---------------------------------------------------------------------------
control SwitchIngress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    // 1、处理metadata_t：问题，tcp和udp怎么区分开？  ig_md 要在action或者apply里才能使用
    // ig_md.keyCarried = hdr.ipv4.src_addr ++ hdr.ipv4.dst_addr ++ hdr.ipv4.protocol ++ hdr.tcp.src_port ++ hdr.tcp.dst_port;
    
    // 2、创建存key的寄存器数组，大小为1024个寄存器
    // Register<T,I>(size_I,T initial_value) register_name;
    // 注意位的格式声明与参数的位置是相反的，T是T initial_value的位声明即寄存器初始值，
    // 而 I 是寄存器个数 size_I 的位声明。T initial_value可以缺省。
    Register<flow_ID_t, bit<10>>(register_array_size, 0) S1_flow_ID_array;
    Register<flow_ID_t, bit<10>>(register_array_size, 0) S2_flow_ID_array;
    Register<flow_ID_t, bit<10>>(register_array_size, 0) S3_flow_ID_array;
    
    // 3、创建存vote+的寄存器数组，大小为1024，单个寄存器宽度为16b
    Register<bit<16>, bit<10>>(register_array_size, 0) S1_yes_vote_array;
    Register<bit<16>, bit<10>>(register_array_size, 0) S2_yes_vote_array;
    Register<bit<16>, bit<10>>(register_array_size, 0) S3_yes_vote_array;
    
    // 4、创建存vote-的寄存器数组，大小为1024，单个寄存器宽度为16b
    Register<bit<16>, bit<10>>(register_array_size, 0) S1_no_vote_array;
    Register<bit<16>, bit<10>>(register_array_size, 0) S2_no_vote_array;
    Register<bit<16>, bit<10>>(register_array_size, 0) S3_no_vote_array;

    // 5、使用hash值计算flowkey的索引
    // ig_md.arrayIndex = Hash<bit<16>>(HashAlgorithm_t.CRC16).get(ig_md.keyCarried) >> 6;

    // 5、RegisterAction
    // 读取flow_ID的RegisterAction
    // RegisterAction<flow_ID_t, bit<10>, flow_ID_t>(S1_flow_ID_array) get_S1_flow_ID_action = {
    //     void apply(inout flow_ID_t val, out flow_ID_t val) {}
    // }


    // stage1的action
    action doStage1() {
        // 先设定key
        if (hdr.tcp.isValid()) {
            ig_md.keyCarried = hdr.ipv4.src_addr ++ hdr.ipv4.dst_addr ++ hdr.ipv4.protocol ++ hdr.tcp.src_port ++ hdr.tcp.dst_port;
            ig_md.carried = true;
        }
        if (hdr.udp.isValid()) {
            ig_md.keyCarried = hdr.ipv4.src_addr ++ hdr.ipv4.dst_addr ++ hdr.ipv4.protocol ++ hdr.udp.src_port ++ hdr.udp.dst_port;
            ig_md.carried = true;
        }
        // 使用hash得到key的index
        ig_md.arrayIndex = Hash<bit<16>>(HashAlgorithm_t.CRC16).get(ig_md.keyCarried) >> 6;

        // 如果 index 处的 key 是空的，将key放进去
        flow_ID_t keyRead = S1_flow_ID_array.read(ig_md.arrayIndex);
        if (keyRead == 0) {
            // 空条目，直接放入
            S1_flow_ID_array.write(ig_md.arrayIndex, ig_md.keyCarried);
        } else {
            // 条目不空
            // 读取 stage1 中对应位置的 key 与计数值，如果 key 一样，就增加赞成票的计数，否则增加反对票的计数
            bit<16> yesVote = S1_yes_vote_array.read(ig_md.arrayIndex);
            bit<16> noVote = S1_no_vote_array.read(ig_md.arrayIndex);

            if (ig_md.keyCarried == S1_flow_ID_array.read(ig_md.arrayIndex)) {
                S1_yes_vote_array.write(ig_md.arrayIndex, yesVote + 1);
                // 如果赞成票超过 1<<16 的一半，认为其是当前时间段内的 HH 流 ====== 有待商榷
                if (yesVote >= (1 << 15)) {
                    // 当前包需要sendCPU() 
                    TODO
                    // 将赞成票与反对票减半，防止此流依然是HH流
                    S1_yes_vote_array.write(ig_md.arrayIndex, yesVote >> 1);
                    S1_no_vote_array.write(ig_md.arrayIndex, noVote >> 1);
                }
                // 下一阶段是否需要处理的标识
                ig_md.carried = false;
            } else {
                S1_no_vote_array.write(ig_md.arrayIndex, noVote + 1);
                // 如果此时反对票超过了赞成票的二倍，就执行处理:
                if (noVote + 1 >= yesVote * 2) {
                    // 1. 交换 flowID
                    flow_ID_t temp = ig_md.keyCarried;
                    ig_md.keyCarried = S1_flow_ID_array.read(ig_md.arrayIndex);
                    S1_flow_ID_array.write(ig_md.arrayIndex, temp);
                    // 2. 把原来的赞成票放到 ig_md 中进入下一阶段， 
                    ig_md.countCarried = yesVote;
                    // 3. 把原来的反对票当作新的赞成票，新的反对票置 0
                    S1_yes_vote_array.write(ig_md.arrayIndex, noVote);
                    S1_no_vote_array.write(ig_md.arrIndex, 0);
                    // *****问题：溢出怎么办？？？
                }
            }
        }
    }
        
    // stage2 的 action
    action doStage2() {
        // 如果 carried 是 false, 说明没有携带数据进来，直接放行
        if (ig_md.carried == false) {
            exit;
        }
        // 可以生成新的 index，也可以使用原来的
        // 如果 index 处的 key 是空的，将key放进去
        flow_ID_t keyRead = S2_flow_ID_array.read(ig_md.arrayIndex);
        if (keyRead == 0) {
            // 空条目，直接放入
            S2_flow_ID_array.write(ig_md.arrayIndex, ig_md.keyCarried);
        } else {
            // 条目不空
            // 读取 stage2 中对应位置的 key 与计数值，如果 key 一样，就增加赞成票的计数，否则增加反对票的计数
            bit<16> yesVote = S2_yes_vote_array.read(ig_md.arrayIndex);
            bit<16> noVote = S2_no_vote_array.read(ig_md.arrayIndex);

            if (ig_md.keyCarried == S2_flow_ID_array.read(ig_md.arrayIndex)) {
                S2_yes_vote_array.write(ig_md.arrayIndex, yesVote + 1);
                // 如果赞成票超过 1<<16 的一半，认为其是当前时间段内的 HH 流 ====== 有待商榷
                if (yesVote >= (1 << 15)) {
                    // 当前包需要sendCPU() 
                    TODO
                    // 将赞成票与反对票减半，防止此流依然是HH流
                    S2_yes_vote_array.write(ig_md.arrayIndex, yesVote >> 1);
                    S2_no_vote_array.write(ig_md.arrayIndex, noVote >> 1);
                }
                // 下一阶段是否需要处理的标识
                ig_md.carried = false;
            } else {
                // 携带的 key 与读到的 key 不一样，增加 反对票
                S2_no_vote_array.write(ig_md.arrayIndex, noVote + 1);
                // 如果此时反对票超过了赞成票的一倍，就执行处理:
                if (noVote + 1 >= yesVote * 2) {
                    // 1. 交换 flowID
                    flow_ID_t temp = ig_md.keyCarried;
                    ig_md.keyCarried = keyRead;
                    S2_flow_ID_array.write(ig_md.arrayIndex, temp);
                    // 2. 把原来的赞成票放到 ig_md 中进入下一阶段， 
                    ig_md.countCarried = S2_yes_vote_array.read(ig_md.arrayIndex);
                    // 3. 把原来的反对票当作新的赞成票，新的反对票置 0
                    S2_yes_vote_array.write(ig_md.arrayIndex, noVote);
                    S2_no_vote_array.write(ig_md.arrIndex, 0);
                    // *****问题：溢出怎么办？？？
                }
            }
        }
    }

    // stage3 的 action
    action doStage3() {
        // 如果 carried 是 false, 说明没有携带数据进来，直接放行
        if (ig_md.carried == false) {
            exit;
        }
        // 可以生成新的 index，也可以使用原来的
        // 如果 index 处的 key 是空的，将key放进去
        flow_ID_t keyRead = S3_flow_ID_array.read(ig_md.arrayIndex);
        if (keyRead == 0) {
            // 空条目，直接放入
            S3_flow_ID_array.write(ig_md.arrayIndex, ig_md.keyCarried);
        } else {
            // 条目不空
            // 读取 stage3 中对应位置的 key 与计数值，如果 key 一样，就增加赞成票的计数，否则增加反对票的计数
            bit<16> yesVote = S3_yes_vote_array.read(ig_md.arrayIndex);
            bit<16> noVote = S3_no_vote_array.read(ig_md.arrayIndex);

            if (ig_md.keyCarried == S3_flow_ID_array.read(ig_md.arrayIndex)) {
                S3_yes_vote_array.write(ig_md.arrayIndex, yesVote + 1);
                // 如果赞成票超过 1<<16 的一半，认为其是当前时间段内的 HH 流 ====== 有待商榷
                if (yesVote >= (1 << 15)) {
                    // 当前包需要sendCPU() 
                    TODO
                    // 将赞成票与反对票减半，防止此流依然是HH流
                    S3_yes_vote_array.write(ig_md.arrayIndex, yesVote >> 1);
                    S3_no_vote_array.write(ig_md.arrayIndex, noVote >> 1);
                }
                // 下一阶段是否需要处理的标识
                ig_md.carried = false;
            } else {
                // 携带的 key 与读到的 key 不一样，增加 反对票
                S3_no_vote_array.write(ig_md.arrayIndex, noVote + 1);
                // 如果此时反对票超过了赞成票的一倍，就执行处理:
                if (noVote + 1 >= yesVote * 2) {
                    // 1. 交换 flowID
                    flow_ID_t temp = ig_md.keyCarried;
                    ig_md.keyCarried = keyRead;
                    S3_flow_ID_array.write(ig_md.arrayIndex, temp);
                    // 2. 把原来的赞成票放到 ig_md 中进入下一阶段， 
                    ig_md.countCarried = S3_yes_vote_array.read(ig_md.arrayIndex);
                    // 3. 把原来的反对票当作新的赞成票，新的反对票置 0
                    S3_yes_vote_array.write(ig_md.arrayIndex, noVote);
                    S3_no_vote_array.write(ig_md.arrIndex, 0);
                    // *****问题：溢出怎么办？？？
                }
            }
        }
    }


    // table TODO
    table votepipe {
        
    }

    // apply TODO
} // control SwitchIngress



// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    apply {
        pkt.emit(hdr);
    }
}

/****** E G R E S S P I P E L I N E ********/

// ---------------------------------------------------------------------------
// Egress Parser
// ---------------------------------------------------------------------------
parser EmptyEgressParser(
        packet_in pkt,
        out empty_header_t hdr,
        out empty_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        transition accept;
    }
}

// ---------------------------------------------------------------------------
// Egress Control
// ---------------------------------------------------------------------------
control EmptyEgress(
        inout empty_header_t hdr,
        inout empty_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {
    apply {}
}

// ---------------------------------------------------------------------------
// Egress Deparser
// ---------------------------------------------------------------------------
control EmptyEgressDeparser(
        packet_out pkt,
        inout empty_header_t hdr,
        in empty_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md) {
    apply {}
}

/****** P I P E L I N E ********/

Pipeline(SwitchIngressParser(),
            SwitchIngress(),
            SwitchIngressDeparser(),
            EmptyEgressParser(),
            EmptyEgress(),
            EmptyEgressDeparser()) pipe;

Switch(pipe) main;