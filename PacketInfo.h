#ifndef _PACKETINFO_H
#define _PACKETINFO_H

#include "SystemDefine.h"
#include "malloc.h"
extern "C" {
#include "BytesTools.h"
#include "NetworkTools.h"
}

struct AppData
{
    // 请调用 bytesToAppData 为 本对象赋值。
    // Example: bytesToAppData("test123",7,& packetInfo->appData);
    unsigned char *payload=NULL;
    unsigned short payload_s;
};

#define PacketType_NO 0
#define PacketType_TCP 6
#define PacketType_UDP 17

class PacketInfo
{
public:
    struct ether_header ethernetHead;
    struct iphdr ipHead;
    struct tcphdr tcpHead;
    struct udphdr udpHead;
    struct AppData appData;
    unsigned int packetType = PacketType_NO;
    ~PacketInfo(){
        if ( this->appData.payload != NULL){
            free(this->appData.payload );
            this->appData.payload = NULL;
        }
    };
};

void bytesToEthernetHead(const char *ethernetBytesHeadPtr,unsigned int len,struct ether_header *ethernetHead)
;

// Only for IPv4, no options.
void bytesToIpHead(const char *ipBytesHeadPtr,unsigned int len,struct iphdr *ipHead)
;

void bytesToTcpHead(const char *tcpBytesHeadPtr,unsigned int len,struct tcphdr *tcpHead)
;

void bytesToAppData(const char *appDataBytesHeadPtr,unsigned int len,struct AppData *appData)
;

void bytesToPacketInfo(const char* bytesHeadPtr, unsigned int len, PacketInfo *packet)
;

PacketInfo *readableHexStreamToPacketInfo(const char *readableHexStream)
;

PacketInfo *getTcpPacketExample()
;

PacketInfo *getUdpPacketExample()
;

void displayPacketInfo(const PacketInfo *packet)
;

#endif // _PACKETINFO_H
