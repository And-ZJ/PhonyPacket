#include "PlatformTools.h"

int isLittleEndian()
{
    // 高字节存放在高地址
    unsigned short v = 0xabcd;
    unsigned char *c = (unsigned char *) & v;
    if ( (*c) == 0xcd && (*(c+1) == 0xab))
    {
        return 1;
    }
    return 0;
}


