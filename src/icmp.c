#include "icmp.h"

#include "ip.h"
#include "net.h"

/**
 * @brief 发送icmp响应
 *
 * @param req_buf 收到的icmp请求包
 * @param src_ip 源ip地址
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip) {
    // TO-DO
    // 初始化并封装数据：
    size_t data_len = req_buf->len - sizeof(icmp_hdr_t);
    buf_init(&txbuf, data_len);
    //封装 ICMP 报头和数据，其中数据部分直接拷贝来自接收的回显请求报文中的数据
    memcpy(txbuf.data, req_buf->data + sizeof(icmp_hdr_t), data_len);

    buf_add_header(&txbuf, sizeof(icmp_hdr_t));

    icmp_hdr_t *icmp_head = (icmp_hdr_t *)txbuf.data;
    icmp_head->type = ICMP_TYPE_ECHO_REPLY;
    icmp_head->code = 0;
    icmp_head->id16 = ((icmp_hdr_t *)req_buf->data)->id16;
    icmp_head->seq16 = ((icmp_hdr_t *)req_buf->data)->seq16;
    // 填写校验和：
    icmp_head->checksum16 = 0;
    icmp_head->checksum16 = checksum16((uint16_t *)txbuf.data, txbuf.len);
    // 发送数据报：
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip) {
    // TO-DO
    // 报头检测：
    if(buf->len < sizeof(icmp_hdr_t)){
        return ;
    }
    // 查看 ICMP 类型：
    icmp_hdr_t *head = (icmp_hdr_t *)buf->data;
    uint8_t type = head->type;
    if(type != ICMP_TYPE_ECHO_REQUEST){
        return ;
    }
    else{
        // 回送回显应答：
        icmp_resp(buf, src_ip);
    }
}

/**
 * @brief 发送icmp不可达
 *
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code) {
    // TO-DO
    // 初始化并填写报头：
    size_t data_len = sizeof(ip_hdr_t) + 8;
    buf_init(&txbuf, data_len);
    memcpy(txbuf.data, recv_buf->data, data_len);

    buf_add_header(&txbuf, sizeof(icmp_hdr_t));
    icmp_hdr_t *icmp_head = (icmp_hdr_t *)txbuf.data;
    icmp_head->type = ICMP_TYPE_UNREACH;
    icmp_head->code = code;
    icmp_head->id16 = 0;
    icmp_head->seq16 = 0;
    // 填写数据与校验和：
    icmp_head->checksum16 = 0;
    icmp_head->checksum16 = checksum16((uint16_t *)txbuf.data, txbuf.len);
    // 发送数据报：
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 初始化icmp协议
 *
 */
void icmp_init() {
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}