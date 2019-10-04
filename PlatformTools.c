#include "PlatformTools.h"

int isLittleEndian()
{
    // ���ֽڴ���ڸߵ�ַ
    unsigned short v = 0xabcd;
    unsigned char *c = (unsigned char *) & v;
    if ( (*c) == 0xcd && (*(c+1) == 0xab))
    {
        return 1;
    }
    return 0;
}


