#include "include.h"
#include "icmp.h"
#include "ipv4.h"
#include "utils.h"
#include "ethernet.h"

#include<pthread.h>
#include<map>
/* this normally comes from the pcap.h header file, but we'll just be using
 * a few specific pieces, so we'll add them here
 *
 * The first record in the file contains saved values for some
 * of the flags used in the printout phases of tcpdump.
 */

/* every pcap file starts with this structure */
struct pcap_file_header {
	bpf_u_int32 magic;
	unsigned short version_major;
	unsigned short version_minor;
	bpf_int32 thiszone;	/* gmt to local correction; this is always 0 */
	bpf_u_int32 sigfigs;	/* accuracy of timestamps; this is always 0 */
	bpf_u_int32 snaplen;	/* max length saved portion of each pkt */
	bpf_u_int32 linktype;	/* data link type (LINKTYPE_*) */
};

/*
 * Generic per-packet information, as supplied by libpcap.
 * this is the second record in the file, and every packet starts
 * with this structure (followed by the packet date bytes)
 */
struct pcap_pkthdr {
	bpf_u_int32 ts_secs;		/* time stamp */
	bpf_u_int32 ts_usecs;	/* time stamp */
	bpf_u_int32 caplen;	/* length of portion present */
	bpf_u_int32 len;	/* length of this packet (off wire) */
};


struct interface interfaces[10];
int num_interfaces = 0;
__thread int thread_interface_idx;

char tcp_flag_string[] = "FSRPAU"; 

int debug = 0;
int resolveDNS = 1;
int reverseEndian = 0;

struct pcap_file_header pfh;

/* iov is the array of iovecs that will be used to write the REPLY packets to the pcap file
 * e.g. iov[0] = ethernet, iov[1] = ipv4, iov[2] = icmp, ..., iov[iov_cnt]. 
 * Note that iov[i] only contains the HEADER at the i-th layer. The data of the i-th packet are the i+1-th, i+2-th, etc. packets due to encapsulation.
 * iov_cnt is the number of iovecs in the array used to write ONE COMPLETE (all protocols) REPLY packet to the pcap file
 * iov_cnt is incremented each time a new protocol is added to the REPLY packet, and reset to 0 each time a new COMPLETE REPLY packet is written.
 */
__thread struct iovec iov[10];
__thread int iov_cnt = 0;

/* MAC to IPv4 and IPv6 */
std::map<uint64_t, uint32_t> arp_cache_v4;
std::map<uint64_t, uint64_t> arp_cache_v6;

/* write pcap header + `len` bytes from `data` to the packet capture file `pcap_fd` */
void write_pcap(int interface_idx) {
    struct pcap_pkthdr *pcap_hdr = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
    // write the pcap header
    struct timeval tv;
    long long ret = gettimeofday(&tv, NULL);
    if (ret == -1) {
        perror("gettimeofday");
        return;
    }

    /* calculate the total length of the PCAP packet */
    long long total_len = 0;
    for (int i = 1 ; i < iov_cnt; i++) total_len += iov[i].iov_len;

    pcap_hdr->ts_secs = tv.tv_sec;
    pcap_hdr->ts_usecs = tv.tv_usec;
    pcap_hdr->caplen = total_len;   // length WITHOUT the pcap header
    pcap_hdr->len = total_len;

    iov[0].iov_base = pcap_hdr;
    iov[0].iov_len = sizeof(struct pcap_pkthdr);
    total_len += sizeof(struct pcap_pkthdr);

    ret = writev(interfaces[interface_idx].pcap_fd_write, iov, iov_cnt);
    if (ret != total_len) { // MUST write all bytes to consider it a success
        perror("writev");
        return;
    }

    /* reset the iov array */
    for (int i = 0 ; i < iov_cnt; i++) {
        free(iov[i].iov_base);
        iov[i].iov_base = NULL;
        iov[i].iov_len = 0;
    }
    iov_cnt = 1;
}

/* open .dmp pcap file (2 separate fds for read and write) for the `interface_idx`-th interface and verify its header */
void setup(char *interface_arg, int interface_idx) {
    // get pcap filename in the form X.X.X.0_masklength first, then open pcap it
    int l = strlen(interface_arg);
    char *_filename = (char*)malloc(l + 6);
    if (get_ip_and_filename(interface_arg, _filename, interface_idx) != 0) {
        exit(123);
    }
    int pcap_fd_read = open(_filename, O_RDONLY);
    int pcap_fd_write = open(_filename, O_WRONLY | O_APPEND);
    if (pcap_fd_read < 0 || pcap_fd_write < 0) {
        perror(_filename);
        exit(1);
    }

    /* read the pcap_file_header at the beginning of the file, check it, then print as requested */
    int ret = read(pcap_fd_read, &pfh, sizeof(pfh));
    if (ret <= 0) {
        perror("read");
        exit(1);
    }
    if (ret < (int)sizeof(pfh)) {
        printf("truncated pcap header: only %d bytes\n", ret);
        exit(1);
    }
    if (pfh.magic == PCAP_MAGIC_LITTLE) { // packet is in little-endian
        reverseEndian = 0;
    } else if (pfh.magic == PCAP_MAGIC_BIG) {
        reverseEndian = 1;
    } else {
        fprintf(stderr, "invalid magic number: 0x%08x\n", pfh.magic);
        exit(1);
    }

    // reverse the bytes if the packet was originally in big-endian
    if (reverseEndian) {
        reverse_assign(&pfh.version_major, sizeof(pfh.version_major));
        reverse_assign(&pfh.version_minor, sizeof(pfh.version_minor));
        reverse_assign(&pfh.linktype, sizeof(pfh.linktype));
    }

    if (pfh.version_major != PCAP_VERSION_MAJOR || pfh.version_minor != PCAP_VERSION_MINOR) {
        fprintf(stderr, "invalid pcap version: %d.%d\n", pfh.version_major, pfh.version_minor);
        exit(1);
    }

    printf("header magic: %x\n", PCAP_MAGIC_LITTLE);
    printf("header version: %d %d\n", pfh.version_major, pfh.version_minor);
    printf("header linktype: %d\n\n", pfh.linktype);

    interfaces[interface_idx].pcap_fd_read = pcap_fd_read;
    interfaces[interface_idx].pcap_fd_write = pcap_fd_write;
}

void* loop(void* _interface_idx) {
    int interface_idx = *(int*)_interface_idx;
    thread_interface_idx = interface_idx;
    unsigned char* in_packet = (unsigned char*)malloc(2 << 20);
    int pcap_fd_read = interfaces[interface_idx].pcap_fd_read;
    int pcap_fd_write = interfaces[interface_idx].pcap_fd_write;
    int ret;
	/* now read each packet in the file */
	while (1) {

		/* read the pcap_packet_header, then print as requested */
        struct pcap_pkthdr pph;
        ret = read(pcap_fd_read, &pph, sizeof(pph));
        
        if (ret < 0) {
            perror("read");
            pthread_exit(&ret);
        } else if (ret == 0) {       // EOF, wait a little bit before trying again            
            usleep(10000);
            continue;   
        }
        else if (ret < (int)sizeof(pph)) {
            printf("truncated packet header: only %d bytes\n", ret);
            pthread_exit(&ret);
        }

        if (reverseEndian) {
            reverse_assign(&pph.caplen, sizeof(pph.caplen));
            reverse_assign(&pph.ts_secs, sizeof(pph.ts_secs));
            reverse_assign(&pph.ts_usecs, sizeof(pph.ts_usecs));
        }

        // now read the actual packet
        ret = read(pcap_fd_read, in_packet, pph.caplen);        
        if (ret < 0) {
            perror("read");
            pthread_exit(&ret);
        } else if (ret == 0) break;    // EOF
        else if (ret < (int)pph.caplen) {
            printf("truncated packet: only %d bytes\n", ret);
            pthread_exit(&ret);
        }
        in_packet[ret] = '\0';
        
        if (debug) {
            puts("[+] Received a packet.");
        }
        if (reverseEndian) {
            reverse_assign(&pph.ts_secs, sizeof(pph.ts_secs));
            reverse_assign(&pph.ts_usecs, sizeof(pph.ts_usecs));
            reverse_assign(&pph.len, sizeof(pph.len));
        }

         // some format printing stuffs
        char *tmp = (char*)malloc(30);
        if (!tmp) {
            ret = 1234;
            perror("malloc:");
            pthread_exit(&ret);
        }
        long double f = pph.ts_secs;
        f += (pph.ts_usecs / 1000000.0);
        ret = sprintf(tmp, "%.9Lf", f);
        tmp[ret] = '\0';
		printf("%20s\t%d\t%d\t", tmp, pph.caplen, pph.len);
        free(tmp);

        iov_cnt = 1;
        if (pfh.linktype == 1) { 
		    ret = process_ethernet(in_packet, iov_cnt);
            if (ret < 0) {
                fprintf(stderr, "process_ethernet failed.\n");
                break;
            } else if (ret == 0) {
                if (debug) fprintf(stderr, "process_ethernet returned with 0.\n"); 
                continue;
            }
            write_pcap(pcap_fd_write);
        } 
	}
    pthread_exit(&ret);
}

void print_help() {
    printf("Usage: ./twig [-d] [-d] [-d] [-i] IPv4addr_masklength\n");
    printf("\t-i:\t{IPv4addr}_{mask length} e.g. 192.168.1.10_24.\n");
    printf("\t\tTwig should assume that it has IP address 192.168.1.10/24 on that interface and that it should use the following file for reading and writing packets: 192.168.1.0 24.dmp\n");
    printf("\t-d:\tDebugging flag. Can be used up to 3 times to increase verbosity. e.g. ./twig -d -d -d -i 192.168.1.10_24.\n");
    printf("\t-h:\tPrint this help message.\n");
    exit(0);
}


int main(int argc, char *argv[])    
{
	char *interface_arg = NULL;
    if (argc < 2) {
        fprintf(stderr, "No interface provided. Check -i option.\n");
        print_help();
        exit(99);
    }

	for (int i = 1 ; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0) {
            debug++;
        } else if (strcmp(argv[i], "-i") == 0) {
            i++;
            interface_arg = argv[i];
            if (interface_arg == NULL) {
                fprintf(stderr, "No interface provided. Check -i option.\n");
                print_help();
                exit(99);
            }
            setup(interface_arg, num_interfaces);
            num_interfaces++;
        } else if (strcmp(argv[i], "-h") == 0) {
            print_help();
            exit(0);
        } else {
            fprintf(stderr, "Unknown argument: %s\n", argv[i]);
            print_help();
            exit(99);
        }
    }

    pthread_t threads[num_interfaces];
    int ret;
    for (int i = 0 ; i < num_interfaces; i++) {
        ret = pthread_create(&threads[i], NULL, loop, (void*)&i);
        if (ret < 0) {
            fprintf(stderr, "[!] Failed to create thread for interface %d. ABORTING!!!\n", i);
            exit(1337);
        }
    }

    for (int i = 0 ; i < num_interfaces; i++) {
        int *ret_ptr;
        ret = pthread_join(threads[i], (void**)&ret_ptr);
        if (ret != 0) {
            perror("pthread_join");
            exit(1338);
        }
        printf("pthread_join: thread %d exitted with status %d\n", i, *ret_ptr);
    }
    return 0;
}

