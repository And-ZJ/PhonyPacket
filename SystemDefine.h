#ifndef _SYSTEM_DEFINE_H
#define _SYSTEM_DEFINE_H

#ifdef __linux__


#include <net/ethernet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#else

#define ETH_ALEN 6

struct ether_header
{
    unsigned char ether_dhost[ETH_ALEN];	/* destination eth addr	*/
    unsigned char ether_shost[ETH_ALEN];	/* source ether addr	*/
    unsigned short ether_type;		        /* packet type ID field	*/
};

struct iphdr
{
#if defined(__LITTLE_ENDIAN_BITFIELD)
    unsigned char	ihl:4,
               version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
    unsigned char	version:4,
               ihl:4;
#else
    unsigned char	ihl:4,
               version:4;
#endif
    unsigned char tos;
    unsigned short tot_len;
    unsigned short id;
    unsigned short frag_off;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short check;
    unsigned int saddr;
    unsigned int daddr;
    /*The options start here. */
};

struct tcphdr
{
    unsigned short source;
    unsigned short dest;
    unsigned int seq;
    unsigned int ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
    unsigned short res1:4,
             doff:4,
             fin:1,
             syn:1,
             rst:1,
             psh:1,
             ack:1,
             urg:1,
             ece:1,
             cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
    unsigned short doff:4,
             res1:4,
             cwr:1,
             ece:1,
             urg:1,
             ack:1,
             psh:1,
             rst:1,
             syn:1,
             fin:1;
#else
    unsigned short res1:4,
             doff:4,
             fin:1,
             syn:1,
             rst:1,
             psh:1,
             ack:1,
             urg:1,
             ece:1,
             cwr:1;
#endif // defind
    unsigned short window;
    unsigned short check;
    unsigned short urg_ptr;
};

struct udphdr {
	unsigned short 	source;
	unsigned short 	dest;
	unsigned short 	len;
	unsigned short 	check;
};

#endif // __linux__

#endif // _SYSTEM_DEFINE_H


