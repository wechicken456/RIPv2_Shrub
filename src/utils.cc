#include "utils.h"



// any network-layer field > 8-bit will have to be reversed before use since network packets are in big-endian
// and our machine is little-endian
void reverse_assign(void *_ptr, int len) {
    unsigned char *ptr = (unsigned char*)_ptr;
    unsigned char tmp;
    for (int i = 0 ; i < (int)(len / 2); i++) {
        tmp = ptr[i];
        ptr[i] = ptr[len-i-1];
        ptr[len-i-1] = tmp;
    }
}

// do a reverse DNS look up to get host name from IP address
void print_hostname(uint8_t *ipv4_addr) {
    struct sockaddr_in *sa = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
    struct in_addr sin_addr = {*(uint32_t*)ipv4_addr};
    sa->sin_addr = sin_addr;
    sa->sin_family = AF_INET;
    char host[1024];
    memset(host, 0, 1024);
    char serv[1024];
    memset(serv, 0, 1024);
    if (getnameinfo((struct sockaddr*)sa, sizeof(struct sockaddr_in), host, 1023, serv, 1023, 0)) 
        printf("\t");
    else 
        printf("(%s)\t", host);

}

void print_addr_6(uint8_t *addr) {
    for (int i = 0 ; i < 5; i++) {
        printf("%02x:", addr[i]);
    }
    printf("%02x", addr[5]);
}

void print_addr_4(uint8_t *addr) {
    for (int i = 0 ; i < 3; i++) {
        printf("%u.", addr[i]);
    }
    printf("%u", addr[3]);
}

// convert an IP string "X.X.X.X" to a binary buffer, and assign it to out_ipv4_addr
int ip_string_to_uint(char *ip_str, uint32_t *out_ipv4_addr) {
    struct sockaddr_in sa;
    if (inet_pton(AF_INET, ip_str, &(sa.sin_addr)) != 1) {  // 1 is for success
        return -1;
    }
    *out_ipv4_addr = ntohl(sa.sin_addr.s_addr);
    return 0;
}
// extract X.X.X.Y and X.X.X.0_24 from X.X.X.Y_24. 
// The first one is our assigned the ip address, while the 2nd one is the name of the .dmp file to read/write network traffic from.
// Write the extracted IPv4 addr and mask length to the interface struct at interface_idx.
// return 0 if success, anything otherwise.
int get_ip_and_filename(char *in_str, char *out_filename, int interface_idx) {
    char *input_copy = strdup(in_str);
    
    char *ip_addr_end = strchr(input_copy, (int)'_');
    char *mask_length = ip_addr_end + 1;
    interfaces[interface_idx].mask_length = atoi(mask_length);
    if (ip_addr_end != NULL) {         
        *ip_addr_end = '\0'; // now input_copy is '_' -truncated
        if (ip_string_to_uint(input_copy, &interfaces[interface_idx].ipv4_addr) != 0) {    // extract host ip address, also check if the provided X.X.X.Y is valid IP string
            return -1;
        }
        
        strrchr(input_copy, '.')[0] = '\0'; // replace the last '.' with '0' to get the network address
        int l = sprintf(out_filename, "%s.0_%d.dmp", input_copy, interfaces[interface_idx].mask_length);
        if (l < 0) {
            return -1;
        }
        return 0;
    }
    return -1;
}
	
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
unsigned short in_cksum(const unsigned short *addr, int len, unsigned short csum) {
    unsigned int rem = len;
    const unsigned short *w = addr;
    unsigned short ret;
    int sum = csum;

    while (rem > 1) {
        sum += *w++;
        rem -= 2;
    }

    if (rem == 1) { // there might be an odd number of bytes in the header
        sum += *(unsigned char*)w;
    }

    sum = (sum >> 16) + (sum & 0xFFFF); // step 2
    sum += (sum >> 16); // step 3
    ret = ~sum;         // ret is 16-bit, so we truncate sum to 16-bit here
    return ret;
}


int verify_cksum(void *data, int len) {
    return in_cksum((const unsigned short *)data, len, 0) == 0xFFFF;
}
