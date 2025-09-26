#ifndef UTILS_H
#define UTILS_H

#include "include.h"

void print_hostname(uint8_t *ipv4_addr);
void print_addr_4(uint8_t *addr);
void print_addr_6(uint8_t *addr);

int ip_string_to_uint(char *ip_str, uint32_t *out_ipv4_addr);
int get_ip_and_filename(char *in_str, char *out_filename, int interface_idx); 
int get_ip_from_filename(char *in_str, uint32_t *out_ipv4_addr) ;
void reverse_assign(void *_ptr, int len); 
/* compute checksum for an incoming requesta
Initially, the checksum field of the sender is 0.
treat the packet header (NOT including the data( as words (1 word = 2 bytes) add them together (see below), then take 1's complement of the sum.
Let S = sum, ~S = cksum = 1's complement of S.
both are 2-byte or 16-bit.
Then, the sender sends ~S.

Adding algorithm for sender: 
0. Everything is unsigned
1. Use a 32-bit accumulator, and add 2-byte quantities together. 
    - Use 32-bit acc instead of 16 cause we need to store the carry.
2. Add the top 16-bit (which is the carry of the lower 16-bit) to the lower 16-bit. Store this in the same accumulator.
3. Step 2 might produce a carry, so repeat step 2 once more. This is S.
4. Store ~S in the checksum field. 

The receiver does the same computation. All the headers, except for the received cksum, add up to S. 
Then, when we add ~S: S + ~S = 0xFFFF. Take 1's complement = ~0xFFFF = 0. 
=> cksum correct
*/ 
unsigned short in_cksum(const unsigned short *addr, int len, unsigned short csum); 
int verify_cksum(void *data, int len);

int get_interface_for_route(uint32_t dst_addr);
#endif