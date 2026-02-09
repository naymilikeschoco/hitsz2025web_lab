#include "udp.h"

#include "icmp.h"
#include "ip.h"

/**
 * @brief udp处理程序表
 *
 */
map_t udp_table;

/**
 * @brief 处理一个收到的udp数据包
 *
 * @param buf 要处理的包
 * @param src_ip 源ip地址
 */
void udp_in(buf_t *buf, uint8_t *src_ip) {
    // TO-DO
    //Step1 包检查：
    udp_hdr_t *head = (udp_hdr_t *)buf->data;
    if(buf->len < sizeof(udp_hdr_t)){
        return ;
    }

    uint16_t total_len = swap16(head->total_len16);
    if (buf->len < total_len) {
        return;
    }
    //Step2 重新计算校验和：
    uint16_t rec_checksum = head->checksum16;
    head->checksum16 = 0;
    uint16_t calc_checksum = transport_checksum(NET_PROTOCOL_UDP, buf, src_ip, net_if_ip);
    if(rec_checksum != calc_checksum){
        head->checksum16 = rec_checksum;
        return ;
    }
    head->checksum16 = rec_checksum;
    //Step3 查询处理函数：
    uint16_t dst_port = swap16(head->dst_port16);
    udp_handler_t *handler = (udp_handler_t *)map_get(&udp_table, &dst_port);
    if(handler != NULL){
        //Step5 调用处理函数：
        buf_remove_header(buf, sizeof(udp_hdr_t));
        (*handler)(buf->data, buf->len, src_ip, swap16(head->src_port16));
    }else{
        //Step4 处理未找到处理函数的情况：
        buf_add_header(buf, sizeof(ip_hdr_t));
        icmp_unreachable(buf, src_ip, ICMP_CODE_PORT_UNREACH);
        return ;
    }
}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的包
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_out(buf_t *buf, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port) {
    // TO-DO
    //Step1 添加 UDP 报头：
    buf_add_header(buf, sizeof(udp_hdr_t));
    //Step2 填充 UDP 首部字段：
    udp_hdr_t *udp_head = (udp_hdr_t *)buf->data;
    udp_head->src_port16 = swap16(src_port);
    udp_head->dst_port16 = swap16(dst_port);
    uint16_t udp_len = buf->len;
    udp_head->total_len16 = swap16(udp_len);
    //Step3 计算并填充校验和：
    udp_head->checksum16 = 0;
    udp_head->checksum16 = transport_checksum(NET_PROTOCOL_UDP, buf, net_if_ip, dst_ip);
    //Step4 发送 UDP 数据报：
    ip_out(buf, dst_ip, NET_PROTOCOL_UDP);
}

/**
 * @brief 初始化udp协议
 *
 */
void udp_init() {
    map_init(&udp_table, sizeof(uint16_t), sizeof(udp_handler_t), 0, 0, NULL, NULL);
    net_add_protocol(NET_PROTOCOL_UDP, udp_in);
}

/**
 * @brief 打开一个udp端口并注册处理程序
 *
 * @param port 端口号
 * @param handler 处理程序
 * @return int 成功为0，失败为-1
 */
int udp_open(uint16_t port, udp_handler_t handler) {
    return map_set(&udp_table, &port, &handler);
}

/**
 * @brief 关闭一个udp端口
 *
 * @param port 端口号
 */
void udp_close(uint16_t port) {
    map_delete(&udp_table, &port);
}

/**
 * @brief 发送一个udp包
 *
 * @param data 要发送的数据
 * @param len 数据长度
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_send(uint8_t *data, uint16_t len, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port) {
    buf_init(&txbuf, len);
    memcpy(txbuf.data, data, len);
    udp_out(&txbuf, src_port, dst_ip, dst_port);
}