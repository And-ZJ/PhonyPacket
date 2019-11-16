#include "PacketInfo.h"



void bytesToEthernetHead(const char *ethernetBytesHeadPtr,unsigned int len,struct ether_header *ethernetHead)
{
    if (len < 14)
    {
        return;
    }
    assert(ethernetBytesHeadPtr != NULL);
    assert(ethernetHead != NULL);

    copyBytes(ethernetHead->ether_dhost,ethernetBytesHeadPtr,6);
    copyBytes(ethernetHead->ether_shost,ethernetBytesHeadPtr+6,6);



    unsigned short type = bytesToUShort(ethernetBytesHeadPtr+12);

    ethernetHead->ether_type = type;
}


// Only for IPv4, no options.
void bytesToIpHead(const char *ipBytesHeadPtr,unsigned int len,struct iphdr *ipHead)
{
    if (len < 20)
    {
        return;
    }
    assert(ipBytesHeadPtr != NULL);
    assert(ipHead != NULL);

    unsigned int offset = 0;
    ipHead->version = bytesHigh4BitsToUChar(ipBytesHeadPtr + offset);
    ipHead->ihl = *(ipBytesHeadPtr + offset) & 0x0F;
    offset += 1;
    ipHead->tos = *(ipBytesHeadPtr + offset);
    offset += 1;
    ipHead->tot_len = bytesToUShort(ipBytesHeadPtr + offset);
    offset += 2;
    ipHead->id = bytesToUShort(ipBytesHeadPtr + offset);
    offset += 2;
    ipHead->frag_off = bytesToUShort(ipBytesHeadPtr + offset);
    offset += 2;
    ipHead->ttl = *(ipBytesHeadPtr + offset);
    offset += 1;
    ipHead->protocol = *(ipBytesHeadPtr + offset);
    offset += 1;
    ipHead->check = bytesToUShort(ipBytesHeadPtr + offset);
    offset += 2;
    ipHead->saddr = ipNumArrayToIpUInt((const unsigned char *)ipBytesHeadPtr + offset);
    offset += 4;
    ipHead->daddr = ipNumArrayToIpUInt((const unsigned char *)ipBytesHeadPtr + offset);

}

void bytesToTcpHead(const char *udpBytesHeadPtr,unsigned int len,struct udphdr *udphead)
{
    if (len < 8)
    {
        return;
    }
    assert(udpBytesHeadPtr != NULL);
    assert(udphead != NULL);
    unsigned int offset = 0;
    udphead->source = bytesToUShort(udpBytesHeadPtr+offset);
    offset += 2;
    udphead->dest = bytesToUShort(udpBytesHeadPtr+offset);
    offset += 2;
    udphead->len = bytesToUShort(udpBytesHeadPtr+offset);
    offset += 2;
    udphead->check = bytesToUShort(udpBytesHeadPtr+offset);
}

void bytesToTcpHead(const char *tcpBytesHeadPtr,unsigned int len,struct tcphdr *tcpHead)
{
    if (len < 20)
    {
        return;
    }
    assert(tcpBytesHeadPtr != NULL);
    assert(tcpHead != NULL);

    unsigned int offset = 0;
    tcpHead->source = bytesToUShort(tcpBytesHeadPtr+offset);
    offset += 2;
    tcpHead->dest = bytesToUShort(tcpBytesHeadPtr+offset);
    offset += 2;
    tcpHead->seq = bytesToUInt(tcpBytesHeadPtr+offset);
    offset += 4;
    tcpHead->ack_seq = bytesToUInt(tcpBytesHeadPtr+offset);
    offset += 4;
    tcpHead->doff = bytesHigh4BitsToUChar(tcpBytesHeadPtr+offset);
    tcpHead->res1 = bytesLow4BitsToUChar(tcpBytesHeadPtr+offset);
    offset += 1;
    tcpHead->fin = bytesNthBitToUChar(tcpBytesHeadPtr+offset,1);
    tcpHead->syn = bytesNthBitToUChar(tcpBytesHeadPtr+offset,2);
    tcpHead->rst = bytesNthBitToUChar(tcpBytesHeadPtr+offset,3);
    tcpHead->psh = bytesNthBitToUChar(tcpBytesHeadPtr+offset,4);
    tcpHead->ack = bytesNthBitToUChar(tcpBytesHeadPtr+offset,5);
    tcpHead->urg = bytesNthBitToUChar(tcpBytesHeadPtr+offset,6);
    tcpHead->ece = bytesNthBitToUChar(tcpBytesHeadPtr+offset,7);
    tcpHead->cwr = bytesNthBitToUChar(tcpBytesHeadPtr+offset,8);
    offset += 1;
    tcpHead->window = bytesToUShort(tcpBytesHeadPtr+offset);
    offset += 2;
    tcpHead->check = bytesToUShort(tcpBytesHeadPtr+offset);
    offset += 2;
    tcpHead->urg_ptr = bytesToUShort(tcpBytesHeadPtr+offset);
}

void bytesToAppData(const char *appDataBytesHeadPtr,unsigned int len,struct AppData *appData)
{
    if (len <= 0)
    {
        appData->payload = NULL;
        return;
    }
    assert(appDataBytesHeadPtr != NULL);
    assert(appData != NULL);

    appData->payload = (unsigned char *) malloc(sizeof(unsigned char)*len);
    appData->payload_s = len;
    copyBytes(appData->payload,appDataBytesHeadPtr,len);
}

void bytesToPacketInfo(const char* bytesHeadPtr, unsigned int len, PacketInfo *packet)
{

    const char *ethernetBytesHeadPtr = bytesHeadPtr;
    unsigned int totalLen = len;
    bytesToEthernetHead(ethernetBytesHeadPtr,totalLen,& packet->ethernetHead);

    const char *ipBytesHeadPtr = bytesHeadPtr+14;
    totalLen = totalLen-14;
    bytesToIpHead(ipBytesHeadPtr,totalLen,& packet->ipHead);

    const char *appDataBytesHeadPtr = 0;


    if (packet->ipHead.protocol == PacketType_TCP)
    {
        const char *tcpBytesHeadPtr = ipBytesHeadPtr+20;
        totalLen = totalLen-20;
        bytesToTcpHead(tcpBytesHeadPtr,totalLen,& packet->tcpHead);

        appDataBytesHeadPtr = tcpBytesHeadPtr+20;
        totalLen = totalLen-20;
    }
    else if (packet->ipHead.protocol == PacketType_UDP)
    {
        const char *udpBytesHeadPtr = ipBytesHeadPtr+20;
        totalLen = totalLen-20;
        bytesToTcpHead(udpBytesHeadPtr,totalLen,& packet->udpHead);

        appDataBytesHeadPtr = udpBytesHeadPtr+8;
        totalLen = totalLen-8;
    }
    else
    {
        printf("Unknown Protocol.");
    }

    bytesToAppData(appDataBytesHeadPtr,totalLen,& packet->appData);
}

PacketInfo *readableHexStreamToPacketInfo(const char *readableHexStream)
{
    unsigned int captureHexStreamLen = strlen(readableHexStream);

    char *captureBytes = NULL;
    unsigned int captureBytesLen = readableHexStreamToBytes(readableHexStream, captureHexStreamLen, &captureBytes);

    PacketInfo *packet = new PacketInfo();
    bytesToPacketInfo(captureBytes,captureBytesLen,packet);
    free(captureBytes);
    return packet;
}

PacketInfo *getTcpPacketExample()
{
    const char *captureHexStream = "00cfe04a9bfd2c4d54eddd0a080045000430ecc74000800674a1c0100ab5c0100a8900871b32008c53908490074a501810044a84000005000203100000000804000006000000f003000000000000010000000000000000000200d8030000d80300004d454f5704000000a301000000000000c0000000000000463903000000000000c00000000000004600000000b0030000a00300000000000001100800cccccccc6000000000000000a00300007000000000000000020000000200000000000000000000000000000000000000000002000400020000000000020000003903000000000000c000000000000046b601000000000000c00000000000004602000000200100001002000001100800cccccccc10010000000000000100000000000200040002000800020001000000506d48132148d211a4943cb306c100000100000000000000010000000c000200d4000000d40000004d454f5701000000506d48132148d211a4943cb306c100000000000005000000b48039857c064b475330d7f5b845bb30021c0000ec343045b0ff754d44ad168d4800320007004400450053004b0054004f0050002d004d0039005000320048004d004400000007003100390032002e00310036002e00310030002e00310038003100000007003100360039002e003200350034002e003100300039002e00310038003200000000000900ffff00001e00ffff00001000ffff00000a00ffff00001600ffff00001f00ffff00000e00ffff0000000001100800cccccccc00020000000000000000000000000200b48039857c064b470400020000980000ec343045569ee56ae5e4ca3a0100000005000700e4000000e400470007004400450053004b0054004f0050002d004d0039005000320048004d0044005b00350034003800370030005d00000007003100390032002e00310036002e00310030002e003100380031005b00350034003800370030005d00000007003100360039002e003200350034002e003100300039002e003100380032005b00350034003800370030005d00000000000a00ffff4400450053004b0054004f0050002d004d0039005000320048004d0044005c00570069006e00690067006800740000001e00ffff4400450053004b0054004f0050002d004d0039005000320048004d0044005c00570069006e00690067006800740000001000ffff4400450053004b0054004f0050002d004d0039005000320048004d0044005c00570069006e00690067006800740000000900ffff4400450053004b0054004f0050002d004d0039005000320048004d0044005c00570069006e00690067006800740000001600ffff4400450053004b0054004f0050002d004d0039005000320048004d0044005c00570069006e00690067006800740000001f00ffff4400450053004b0054004f0050002d004d0039005000320048004d0044005c00570069006e006900670068007400000000000000000000000000";

    PacketInfo *packet = readableHexStreamToPacketInfo(captureHexStream);

    return packet;
}

PacketInfo *getUdpPacketExample()
{
    const char *captureHexStream = "94de802ff2dd182001954600080045000223ee9c000040110000c0100a47b6fe21960fac1f40020fa50c02380300b94ffa3e89b35502000000012e0100006935f0bd90ff58bb8c6ac28a41e0b8efb4a09f4b5715e5a7e34daa46c7f8fabc050c7ec81cbea23fbe20501d42f9e4e5c739645af637f829ccfca1af8e940b8a1e9e1270fc250183fb275e813f5de26eb24f514749ed8cdb4ef95ea208ffca12fb3b9f0d774207128a7c4e3b9ac500e4cedc16c7e70be82e970a65cf816f87b7f3555e72c881bed2c55ed9c5015c2472ba19e68b33d94d9661d9df3322cc97a03d36b34c658a93850669fe95abec80c45e515a373f7017a22233e077e24b2eabda5d28eb35fc5d1b7f9c00a85e232deca9acb3d304f934d652750267b2fcd2bcfdb8d9f0c2e85d9d4f14035b2f190e2be015c851b9649dc7de8e86440835696876fbc676232f23c81f7e70396165b8aedbbeed83d2d99c48b69fb33d9bf43b4f9a988cd840fa172fa6a1843a6d8f282cc24380b164c988c98a28a9b367605b7c7f8e6795304b81e09ee7543c264ae405cb33e3f1b56a3b9c6a0d19ea8324a21f68dd3a5a896f838dd688e2753e1bba846d2c0107e859ddf545a3573b08b3cc95c78f27553cf79d2517c8c7c4e8ef559144bf7d4ad236e8efad5fd9872aa306d01b6145d8dd53a536290c5c5ac09e126f4a974c6195e2040591401fd0580fe13739b9885cd9366ab82182e924a17531abcaf168807bfe74bd025b5a6f209c074d2480028a13151b72d745cf289bfc625c4c3103";
    PacketInfo *packet = readableHexStreamToPacketInfo(captureHexStream);

    return packet;
}

void displayPacketInfo(const PacketInfo *packet)
{
    printf("Packet Info:\n");

    printf("\tEthernet:\n");
    unsigned char *dstMac = (unsigned char *)packet->ethernetHead.ether_dhost;
    printf("\t\tDstMac = %02x:%02x:%02x:%02x:%02x:%02x\n",dstMac[0],dstMac[1],dstMac[2],dstMac[3],dstMac[4],dstMac[5]);
    unsigned char *srcMac = (unsigned char *)packet->ethernetHead.ether_shost;
    printf("\t\tSrcMac = %02x:%02x:%02x:%02x:%02x:%02x\n",srcMac[0],srcMac[1],srcMac[2],srcMac[3],srcMac[4],srcMac[5]);
    printf("\t\tType = 0x%04x\n",packet->ethernetHead.ether_type);

    printf("\tIP:\n");
    printf("\t\tVersion = 0x%02x\n",packet->ipHead.version);
    printf("\t\tHeadLength = %d (B)\n",packet->ipHead.ihl * 4);
    printf("\t\tTos = 0x%02x\n",packet->ipHead.tos);
    printf("\t\tTotalLength = %d (B)\n",packet->ipHead.tot_len);
    printf("\t\tIdentification = 0x%04x\n",packet->ipHead.id);
    printf("\t\tFragment = 0x%04x\n",packet->ipHead.frag_off);
    printf("\t\tTimeToLive = %d\n",packet->ipHead.ttl);
    printf("\t\tProtocol = %d\n",packet->ipHead.protocol);
    printf("\t\tCheckSum = 0x%04x\n",packet->ipHead.check);
    unsigned char *srcIpArray = ipUIntToIpNumArray(packet->ipHead.saddr);
    printf("\t\tSrcIp = %d.%d.%d.%d\n",srcIpArray[0],srcIpArray[1],srcIpArray[2],srcIpArray[3]);
    unsigned char *dstIpArray = ipUIntToIpNumArray(packet->ipHead.daddr);
    printf("\t\tDstIp = %d.%d.%d.%d\n",dstIpArray[0],dstIpArray[1],dstIpArray[2],dstIpArray[3]);

    if (packet->ipHead.protocol == PacketType_TCP)
    {
        printf("\tTCP:\n");
        printf("\t\tSrcPort = %d\n",packet->tcpHead.source);
        printf("\t\tDstPort = %d\n",packet->tcpHead.dest);
        printf("\t\tSeqNum = 0x%08x\n",packet->tcpHead.seq);
        printf("\t\tAckNum = 0x%08x\n",packet->tcpHead.ack_seq);
        printf("\t\tHeadLength = %d (B)\n",packet->tcpHead.doff * 4);
        printf("\t\tTCP Flags:\n");
        printf("\t\t\tNon = %d\n",uCharNthBitToUChar(packet->tcpHead.res1,1));
        printf("\t\t\tCwr = %d\n",packet->tcpHead.cwr);
        printf("\t\t\tEce =  %d\n",packet->tcpHead.ece);
        printf("\t\t\tUrg =   %d\n",packet->tcpHead.urg);
        printf("\t\t\tAck =    %d\n",packet->tcpHead.ack);
        printf("\t\t\tPsh =     %d\n",packet->tcpHead.psh);
        printf("\t\t\tRst =      %d\n",packet->tcpHead.rst);
        printf("\t\t\tSyn =       %d\n",packet->tcpHead.syn);
        printf("\t\t\tFin =        %d\n",packet->tcpHead.fin);
        printf("\t\tWindowSize = %d\n",packet->tcpHead.window);
        printf("\t\tCheckSum = 0x%04x\n",packet->tcpHead.check);
        printf("\t\tUrgPtr = 0x%04x\n",packet->tcpHead.urg_ptr);
    }
    else if (packet->ipHead.protocol == PacketType_UDP)
    {
        printf("\tUDP:\n");
        printf("\t\tSrcPort = %d\n",packet->udpHead.source);
        printf("\t\tDstPort = %d\n",packet->udpHead.dest);
        printf("\t\tLength = %d\n",packet->udpHead.len);
        printf("\t\tCheckSum = 0x%04x\n",packet->udpHead.check);
    }
    else
    {
        printf("\tUnknown Type: %d\n", packet->ipHead.protocol);
    }

    printf("\tAppData: %d (B)\n",packet->appData.payload_s);
    printf("\t\t");
    displayBytesInHexChars(packet->appData.payload,packet->appData.payload_s);

}


