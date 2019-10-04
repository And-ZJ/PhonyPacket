#include "NetworkTools.h"
#include "BytesTools.h"


unsigned char *ipUIntToIpNumArray(const unsigned int num)
{
    unsigned char *ipNumArray = (unsigned char *)malloc(sizeof(unsigned char)*5);
    ipNumArray[0] = uInt1_8BitsToUChar(num);
    ipNumArray[1] = uInt9_16BitsToUChar(num);
    ipNumArray[2] = uInt17_24BitsToUChar(num);
    ipNumArray[3] = uInt25_32BitsToUChar(num);
    ipNumArray[4] = '\0';
    return ipNumArray;
}

unsigned int ipNumArrayToIpUInt(const unsigned char *ipNumArray)
{
    return fourBytesToUInt((const char)ipNumArray[3],(const char)ipNumArray[2],(const char)ipNumArray[1],(const char)ipNumArray[0]);
}

// 192 16 10 137 -> 0x890a10c0
unsigned int ipNumToIpUInt(const unsigned int n1,const unsigned int n2,const unsigned int n3,const unsigned int n4)
{
    return fourBytesToUInt((const char)n4,(const char)n3,(const char)n2,(const char)n1);
}

unsigned char composeTcpFlags(unsigned char cwr,unsigned char ece,unsigned char urg,unsigned char ack,
                              unsigned char psh,unsigned char rst,unsigned char syn,unsigned char fin)
{
    return (unsigned char) ( ((cwr & 0x01) << 7) | ((ece & 0x01) << 6) | ((urg & 0x01) << 5) | ((ack & 0x01) << 4) |
                             ((psh & 0x01) << 3) | ((rst & 0x01) << 2) | ((syn & 0x01) << 1) | ((fin & 0x01)) ) & 0xFF;
}

