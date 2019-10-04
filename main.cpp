#include <stdio.h>
#include <stdlib.h>

extern "C" {
#include "BytesTools.h"
#include "NetworkTools.h"
}
#include "SendPacket.h"

#define __TEST__

#ifdef __TEST__
#include "Test.h"
#endif // __TEST__

void run_exmaple()
{
    PacketInfo *packetExample = getPacketExample();

#ifdef __linux__
//    copyBytes(packetExample->ethernetHead.ether_shost,"\x00\x0c\x29\xcc\x88\xa0",6);
//    copyBytes(packetExample->ethernetHead.ether_dhost,"\x00\x10\xf3\x5f\xf3\x79",6);
//    packetExample->ipHead.saddr = ipNumToIpUInt(192,16,10,205);
//    packetExample->ipHead.daddr = ipNumToIpUInt(192,16,10,202);
    displayPacketInfo(packetExample);
#endif // __linux__
    int sendSize = sendPacket("ens33",packetExample);
    printf("Send size : %d\n",sendSize);
}

int main()
{
#ifdef __TEST__
    test_all();
#endif // __TEST__

    run_exmaple();

    return 0;
}
