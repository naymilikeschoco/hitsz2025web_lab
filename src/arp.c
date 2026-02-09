#include "arp.h"

#include "ethernet.h"
#include "net.h"

#include <stdio.h>
#include <string.h>
/**
 * @brief 初始的arp包
 *
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = swap16(ARP_HW_ETHER),
    .pro_type16 = swap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 *
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 *
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 *
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp) {
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 *
 */
void arp_print() {
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 *
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip) {
    // TO-DO
    //初始化缓冲区：
    buf_init(&txbuf, sizeof(arp_pkt_t));//对 txbuf 发送缓冲区 进行初始化
    //填写ARP报头:
    arp_pkt_t arp_pkt = arp_init_pkt;
    memcpy(arp_pkt.target_ip, target_ip, NET_IP_LEN);  // 设置目标IP
    //设置操作类型为 ARP_REQUEST，注意进行大小端转换
    arp_pkt.opcode16 = swap16(ARP_REQUEST);
    //发送 ARP 报文：
    memcpy(txbuf.data, &arp_pkt, sizeof(arp_pkt_t));
    txbuf.len = sizeof(arp_pkt_t);
    uint8_t broadcast_mac[NET_MAC_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; //ARP 请求报文为广播报文
    ethernet_out(&txbuf, broadcast_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 发送一个arp响应
 *
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac) {
    // TO-DO
    //初始化缓冲区
    buf_init(&txbuf, sizeof(arp_pkt_t));
    //填写 ARP 报头首部
    arp_pkt_t arp_pkt = arp_init_pkt;
    arp_pkt.opcode16 = swap16(ARP_REPLY);
    memcpy(arp_pkt.target_ip, target_ip, NET_IP_LEN);
    memcpy(arp_pkt.target_mac, target_mac, NET_MAC_LEN);
    //发送 ARP 报文：
    memcpy(txbuf.data, &arp_pkt, sizeof(arp_pkt_t));
    txbuf.len = sizeof(arp_pkt_t);
    ethernet_out(&txbuf, target_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac) {
    // TO-DO
    //检查数据长度：
    if(buf->len < sizeof(arp_pkt_t)){
        return;  // 数据包不完整，将其丢弃
    }
    //报头检查
    arp_pkt_t *arp_pkt = (arp_pkt_t*)buf->data;
    uint16_t hw_type = swap16(arp_pkt->hw_type16);
    uint16_t pro_type = swap16(arp_pkt->pro_type16);
    uint16_t opcode = swap16(arp_pkt->opcode16);

    // 检查硬件类型是否为以太网
    if (hw_type != ARP_HW_ETHER) {
        printf("ARP: Unsupported hardware type, discarding.\n");
        return;
    }

    // 检查上层协议类型是否为IP
    if (pro_type != NET_PROTOCOL_IP) {
        printf("ARP: Unsupported protocol type, discarding.\n");
        return;
    }

    // 检查MAC地址长度是否为6字节
    if (arp_pkt->hw_len != NET_MAC_LEN) {
        printf("ARP: Invalid MAC length, discarding.\n");
        return;
    }

    // 检查IP地址长度是否为4字节
    if (arp_pkt->pro_len != NET_IP_LEN) {
        printf("ARP: Invalid IP length, discarding.\n");
        return;
    }

    // 检查操作类型是否为合法的请求或响应
    if (opcode != ARP_REQUEST && opcode != ARP_REPLY) {
        printf("ARP: Invalid opcode, discarding.\n");
        return;
    }
    
    //更新ARP表项
    map_set(&arp_table, arp_pkt->sender_ip, arp_pkt->sender_mac);
    //查看缓存情况:
    buf_t* pending_buf = (buf_t*)map_get(&arp_buf, arp_pkt->sender_ip);
    if (pending_buf != NULL) {
        // 有缓存：将缓存的数据包通过以太网发送
        ethernet_out(pending_buf, arp_pkt->sender_mac, NET_PROTOCOL_IP);
        map_delete(&arp_buf, arp_pkt->sender_ip);
    } else {
        // 无缓存：判断是否为请求本机IP的ARP请求
        // 检查操作类型为请求，且目标IP是本机IP
        if (opcode == ARP_REQUEST && 
            memcmp(arp_pkt->target_ip, net_if_ip, NET_IP_LEN) == 0) {
            // 回应ARP响应报文（目标IP和MAC为发送方的IP和MAC）
            arp_resp(arp_pkt->sender_ip, arp_pkt->sender_mac);
        }
    }
}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 */
void arp_out(buf_t *buf, uint8_t *ip) {
    // TO-DO
    //查找 ARP 表
    uint8_t* mac = (uint8_t*)map_get(&arp_table, ip);
    //找到对应 MAC 地址，将数据包发送给以太网层
    if (mac != NULL) {
        ethernet_out(buf, mac, NET_PROTOCOL_IP);
        return ;
    } else {
        //未找到对应 MAC 地址：进一步判断 arp_buf 中是否已经有包。
        buf_t *bag = (buf_t *)map_get(&arp_buf, ip);
        if (bag != NULL) {
           return ;
        } else {
            map_set(&arp_buf, ip, buf);
            arp_req(ip);
        }
    }
}

/**
 * @brief 初始化arp协议
 *
 */
void arp_init() {
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL, NULL);
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, NULL, buf_copy);
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}