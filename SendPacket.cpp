#include "SendPacket.h"



#ifndef __linux__
int sendPacket(const char *device,PacketInfo *packet)
{
    printf("\nHint:Cannot send packet in Windows system.\n");
    printf("The send device: %s\n",device);
    displayPacketInfo(packet);
    return 0;
}



#else

/**
    apt-get install libnet-dev
    g++ link parameter:-lnet
*/
#include <libnet.h>

int constructHandle(libnet_t *handle,PacketInfo *packet)
{
    libnet_ptag_t eth_tag, ip_tag, tcp_tag, udp_tag;

    if (packet->ipHead.protocol == PacketType_TCP)
    {
        tcp_tag = libnet_build_tcp(
                      packet->tcpHead.source, // source port
                      packet->tcpHead.dest, // dest port
                      packet->tcpHead.seq, // seq
                      packet->tcpHead.ack_seq, // ack
                      composeTcpFlags(packet->tcpHead.cwr, packet->tcpHead.ece, packet->tcpHead.urg, packet->tcpHead.ack,
                                      packet->tcpHead.psh, packet->tcpHead.rst, packet->tcpHead.syn, packet->tcpHead.fin), // control
                      packet->tcpHead.window, // win
                      0, // sum
                      packet->tcpHead.urg_ptr, // urg
                      LIBNET_TCP_H + packet->appData.payload_s, // len
                      packet->appData.payload, // payload
                      packet->appData.payload_s,// payload_s
                      handle, // libnet_t *l
                      0 // libnet_ptag_t ptag
                  );
        if (tcp_tag == -1)
        {
            return (-3);
        }
    }
    else if (packet->ipHead.protocol == PacketType_UDP)
    {
        udp_tag = libnet_build_udp(
            packet->udpHead.source,
            packet->udpHead.dest,
            packet->udpHead.len, /* length */
            0, /* 校验和，此时为0，表示由Libnet自动计算 */
            packet->appData.payload, // payload
            packet->appData.payload_s,// payload_s
            handle, // libnet_t
            0 // new
        );
        if (udp_tag == -1)
        {
            return (-3);
        }
    }
    else
    {
        return -10;
    }


    ip_tag = libnet_build_ipv4(
                 packet->ipHead.tot_len, /* IP协议块的总长*/
                 packet->ipHead.tos, /* tos */
                 packet->ipHead.id, /* id */
                 packet->ipHead.frag_off, /* frag 片偏移 */
                 packet->ipHead.ttl, /* ttl  */
                 packet->ipHead.protocol, /* 上层协议 */
                 0, /* 校验和，此时为0，表示由Libnet自动计算 */
                 packet->ipHead.saddr, /* 源IP地址,网络序 */
                 packet->ipHead.daddr, /* 目标IP地址,网络序 */
                 NULL, /* 负载内容或为NULL */
                 0, /* 负载内容的大小*/
                 handle, /* Libnet句柄 */
                 0 /* 协议块标记可修改或创建,0表示构造一个新的*/
             );
    if(ip_tag == -1)
    {
        return (-4);
    }

    /* 构造一个以太网协议块,只能用于LIBNET_LINK */
    eth_tag = libnet_build_ethernet(
                  packet->ethernetHead.ether_dhost, /* 以太网目的地址 */
                  packet->ethernetHead.ether_shost, /* 以太网源地址 */
                  packet->ethernetHead.ether_type, /* 以太网上层协议类型，此时为IP类型 */
                  NULL, /* 负载，这里为空 */
                  0, /* 负载大小 */
                  handle, /* Libnet句柄 */
                  0 /* 协议块标记，0表示构造一个新的 */
              );
    if(eth_tag == -1)
    {
        return (-5);
    }
    return 0;
}

int sendPacket(const char *device,PacketInfo *packet)
{
    char error[LIBNET_ERRBUF_SIZE];

    libnet_t *handle = nullptr;

    if((handle = libnet_init(LIBNET_LINK, device, error)) == NULL)
        return (-1);

    int conAns = constructHandle(handle,packet);
    if (conAns != 0)
    {
        return (conAns);
    }

    int packet_size = libnet_write(handle); /* 发送已经构造的数据包*/

    libnet_destroy(handle); /* 释放句柄 */
    return packet_size;

}



#endif
