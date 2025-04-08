#ifndef INCLUDE_H
#define INCLUDE_H

//#include <iostream>
//#include <map>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <arpa/inet.h> 
#include <sys/time.h>
#include <stdio.h>

#define PCAP_MAGIC_LITTLE         0xa1b2c3d4
#define PCAP_MAGIC_BIG            0xd4c3b2a1
#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP 0x0806
#define IPV4_TYPE_TCP 0x6
#define IPV4_TYPE_UDP 0x11
#define IPV4_TYPE_ICMP 0x1
#define ICMP_TYPE_ECHO 0x8
#define ICMP_TYPE_ECHO_REPLY 0x0

typedef int32_t bpf_int32;
typedef u_int32_t bpf_u_int32;


extern char tcp_flag_string[]; 
extern uint32_t host_ipv4_addr;
extern int debug;
extern int resolveDNS;
extern int reverseEndian;


#endif
