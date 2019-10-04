#ifndef _NETWORK_TOOLS_H
#define _NETWORK_TOOLS_H

#include "BytesTools.h"


unsigned char *ipUIntToIpNumArray(const unsigned int num)
;

unsigned int ipNumArrayToIpUInt(const unsigned char *ipNumArray)
;

unsigned int ipNumToIpUInt(const unsigned int n1,const unsigned int n2,const unsigned int n3,const unsigned int n4)
;

unsigned char composeTcpFlags(unsigned char cwr,unsigned char ece,unsigned char urg,unsigned char ack,
                              unsigned char psh,unsigned char rst,unsigned char syn,unsigned char fin)
;

#endif // _NETWORK_TOOLS_H
