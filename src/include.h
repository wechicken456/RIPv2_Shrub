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
#include <sys/uio.h>
#include <time.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/wait.h>

#define pb push_back

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
#define UDP_PORT_ECHO 7
#define UDP_PORT_TIME 37
#define UDP_PORT_RIP 520
#define UNIX_TO_1900_EPOCH_OFFSET 2208988800UL
#define MAX_NUM_INTERFACES 100

typedef int32_t bpf_int32;
typedef u_int32_t bpf_u_int32;


struct interface {
    uint32_t ipv4_addr; 
    uint32_t mask_length;
    uint32_t subnet_mask;
    uint32_t ipv6_addr;
    uint8_t mac_addr[6];
    int rip_cache_idx;  /* the index of the rip_cache_v4 entry for this interface */
    int mtu;

    // since we're reading & writing to the same file, we need 2 different FDs 
    // so that the write one can have O_APPEND that will always seek to the EOF to write so we don't overwrite incoming packet
    int pcap_fd_read;
    int pcap_fd_write;
    pthread_mutex_t mutex;
};

extern struct interface interfaces[];
extern int num_interfaces;
extern __thread int thread_interface_idx; 
extern __thread int outgoing_interface_idx;
extern __thread int is_for_us;
extern int default_route_idx;

extern char tcp_flag_string[]; 
extern uint32_t my_ipv4_addr;
extern uint32_t mask_length;
extern int debug;
extern int resolveDNS;
extern int reverseEndian;

/* iov is the array of iovecs that will be used to write the REPLY packets to the pcap file
 * e.g. iov[0] = ethernet, iov[1] = ipv4, iov[2] = icmp, ..., iov[iov_cnt]. 
 * Note that iov[i] only contains the HEADER at the i-th layer. The data of the i-th packet are the i+1-th, i+2-th, etc. packets due to encapsulation.
 * iov_cnt is the number of iovecs in the array used to write ONE COMPLETE (all protocols) REPLY packet to the pcap file
 * iov_cnt is incremented each time a new protocol is added to the REPLY packet, and reset to 0 each time a new COMPLETE REPLY packet is written.
 */
extern __thread struct iovec iov[];
extern __thread int iov_cnt;

extern int SLEEP_TIME_RIP;
// extern __thread struct iovec iov_rip[];
// extern __thread int iov_rip_cnt;
#endif
