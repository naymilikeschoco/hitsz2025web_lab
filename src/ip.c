#include "ip.h"

#include "arp.h"
#include "ethernet.h"
#include "icmp.h"
#include "net.h"

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac) {
    // TO-DO
    // 保留原包内容：
    buf_t original_buf;
    buf_init(&original_buf, buf->len);
    memcpy(original_buf.data, buf->data, buf->len);
    original_buf.len = buf->len;
    // 检查数据包长度：
    if(buf->len < sizeof(ip_hdr_t)){
        return ;
    }
    // 进行报头检测：
    ip_hdr_t *head = (ip_hdr_t *)buf->data;
    if(head->version != 4){
        return ;
    }

    if(swap16(head->total_len16) > buf->len){
        return ;
    }

    // 校验头部校验和：
    uint16_t check1 = head->hdr_checksum16;
    head->hdr_checksum16 = 0;
    uint16_t check2 = checksum16((uint16_t*)head, sizeof(ip_hdr_t));
    if(check1 != check2){
        head->hdr_checksum16 = check1;
        return ;
    }
    head->hdr_checksum16 = check1;

    // 对比目的 IP 地址：
    if(memcmp(head->dst_ip, net_if_ip, NET_IP_LEN) != 0){
        return ;
    }

    // 去除填充字段：
    if(swap16(head->total_len16) < buf->len){
        buf_remove_padding(buf, (buf->len - swap16(head->total_len16)));
    }
    // 去掉 IP 报头：
    uint8_t protocol = head->protocol;
    uint8_t *src = head->src_ip;
    buf_remove_header(buf, sizeof(ip_hdr_t));
    // 向上层传递数据包：
    if(net_in(buf, protocol, src) == -1){
        // 遇到不能识别的协议类型
        icmp_unreachable(&original_buf, src, ICMP_CODE_PROTOCOL_UNREACH);
    }
}
/**
 * @brief 处理一个要发送的ip分片
 *
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf) {
    // TO-DO
    // 增加头部缓存空间：
    buf_add_header(buf, sizeof(ip_hdr_t));
    // 填写头部字段：
    ip_hdr_t *head = (ip_hdr_t *)buf->data;

    head->hdr_len = sizeof(ip_hdr_t) / IP_HDR_LEN_PER_BYTE;//5;
    head->version = IP_VERSION_4;//4;
    head->tos = 0;
    head->total_len16 = swap16(buf->len);
    head->id16 = swap16(id);

    uint16_t fragment_field = (offset / IP_HDR_OFFSET_PER_BYTE);
    if (mf) {
        fragment_field |= IP_MORE_FRAGMENT;
    }
    head->flags_fragment16 = swap16(fragment_field);

    head->ttl = IP_DEFAULT_TTL;//64;
    head->protocol = protocol;
    memcpy(head->src_ip, net_if_ip, NET_IP_LEN);
    memcpy(head->dst_ip, ip, NET_IP_LEN);

    // 计算并填写校验和：
    head->hdr_checksum16 = 0;
    head->hdr_checksum16 = checksum16((uint16_t*)head, sizeof(ip_hdr_t));
    // 发送数据：
    arp_out(buf, ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol) {
    // TO-DO
    // 检查数据报包长：
    size_t mtu = 1500;
    size_t max_data_len = (mtu - sizeof(ip_hdr_t));
    static int ip_id = 0;
    if(buf->len <= max_data_len){
        ip_fragment_out(buf, ip, protocol, ip_id, 0, 0);
    }
    else{
        // 分片处理：
        int total_len = buf->len;
        int offset = 0;
        while(offset < total_len){
            int mf = (offset + max_data_len < total_len) ? 1 : 0;
            // 创建分片副本
            uint16_t frag_len = (mf) ? max_data_len : (total_len - offset);
            buf_t frag_buf;
            buf_init(&frag_buf, frag_len);
            memcpy(frag_buf.data, buf->data + offset, frag_len);
            ip_fragment_out(&frag_buf, ip, protocol, ip_id, offset, mf);
            offset += max_data_len;
        }
    }
    ip_id++;
}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init() {
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}