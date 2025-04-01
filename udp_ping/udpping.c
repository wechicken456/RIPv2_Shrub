/* 
 * udpping.c - send udp echo requests to another host
 * 
 * Author:	Shawn Osteramnn
 * 		Dept. of Computer Sciences
 * 		Purdue University
 * Date:	Thu May 31 15:11:16 1990
 *
 * Copyright (c) 1990 Shawn Osteramnn
 */

#include <stdio.h>
#include <errno.h>
#include <sys/time.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/timeb.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include "udpping.h"

double gettime(void);

struct echobuf {
    int seq;
    unsigned char data[MAX_DATA];
};

/* how long to wait for a packet to be returned, in milliseconds */
#define DEFAULT_MAX_WAIT_MSECS	500


#define DEFAULT_NUM_PACKETS	1000
#define DEFAULT_DATA_SIZE	50
#define DEFAULT_BURST_SIZE	1
#define DEFAULT_TICK_INTERVAL	100
#define TRUE 1
#define FALSE 0
#define NULLTIME -1.0
#define TIMEOUT -2.0

struct echobuf outbuf;
struct echobuf inbuf;

struct packettime *pt;

int num_packets;
int num_packets_rcvd;
int num_packets_sent;
int tick_interval;
int next_tick;
int max_wait_msecs;
Bool verify;
Bool verbose;
Bool stop_on_error;
int data_size;
int burst_size;
int late_receives;
#define DEFAULT_IP_VERSION 4
int ip_version = DEFAULT_IP_VERSION;
char *host;

char *program;


/* local prototypes */
static void PrintResults(void);
static void usage(void);
static void Open(char *host, char *service);
static void Send(void *buf, int len);
static int Recv(void *buf, int len);
static int VerifyBuf(struct echobuf *pbuf, int len);
static void InitBuf(struct echobuf *pbuf);
static void sighandle(int sig);



int
main(
    int argc,
    char **argv)
{
    int i;
    int outseq;

    host = NULLPTR;
    char *service = "echo";
    num_packets = DEFAULT_NUM_PACKETS;
    data_size = DEFAULT_DATA_SIZE;
    burst_size = DEFAULT_BURST_SIZE;
    tick_interval = DEFAULT_TICK_INTERVAL;
    verify = FALSE;
    stop_on_error = FALSE;
    program = argv[0];
    num_packets_rcvd = 0;
    num_packets_sent = 0;
    late_receives = 0;
    max_wait_msecs = DEFAULT_MAX_WAIT_MSECS;

    /* parse the arguments */
    for (i=1; i < argc; ++i) {
	if (strcmp(argv[i],"-p") == 0) {
	    num_packets = atoi(argv[++i]);
	} else if (strcmp(argv[i],"-s") == 0) {
	    stop_on_error = TRUE;
	} else if (strcmp(argv[i],"-b") == 0 && (i+1 < argc)) {
	    data_size = atoi(argv[++i]);
	    if (data_size > MAX_DATA)
		Error("max data size is %d\n", MAX_DATA);
	} else if (strcmp(argv[i],"-B") == 0 && (i+1 < argc)) {
	    burst_size = atoi(argv[++i]);
	} else if (strcmp(argv[i],"-m") == 0 && (i+1 < argc)) {
	    max_wait_msecs = atoi(argv[++i]);
	} else if (strcmp(argv[i],"-t") == 0 && (i+1 < argc)) {
	    tick_interval = atoi(argv[++i]);
	} else if (strcmp(argv[i],"-v") == 0) {
	    verify = TRUE;
	} else if (strcmp(argv[i],"-P") == 0) {
	    service = argv[i+1]; ++i;
	} else if (strcmp(argv[i],"-4") == 0) {
	    ip_version = 4;
	} else if (strcmp(argv[i],"-6") == 0) {
	    ip_version = 6;
	} else if (*argv[i] == '-') {
	    usage();
	} else if (host == NULLPTR) {
	    host = argv[i];
	} else
	    usage();
    }

    if (!host)
	usage();

    Open(host, service);

    Output("Sending %d udp echo requests of size %d to %s on port %s",
	   num_packets, data_size, host, service);
    if (burst_size != 1)
	Output(" (burst = %d)", burst_size);
    Output("\n");

    InitBuf(&inbuf);

    signal(SIGINT,sighandle);
    signal(SIGQUIT,sighandle);
    signal(SIGTERM,sighandle);

    /* allocate the packet time structure */
    pt = (struct packettime *) malloc((1+num_packets) * sizeof(struct packettime));
    if (pt == (struct packettime *) NULL)
	Error("Couldn't malloc %d bytes\n",
	      (1+num_packets) * sizeof(struct packettime));

    /* zero the packet timers */
    for (i=0; i <= num_packets; ++i) 
	pt[i].send_t = pt[i].recv_t = NULLTIME;

    outseq = 1;
    next_tick = tick_interval;
    while (1) {
	if (outbuf.seq + burst_size-1 > num_packets)
	    burst_size = num_packets - outbuf.seq + 1;
		
	/* send the packet(s) */
	for (i=1; i <= burst_size; ++i) {
	    outbuf.seq = outseq;;
	    Send(&outbuf,data_size + sizeof(int));
	    pt[outbuf.seq].send_t = gettime();
	    ++num_packets_sent;
	    ++outseq;
	}

	/* wait for the packet(s) to return */
	for (i=1; i <= burst_size; ++i) {
	    int ret = 0;
	    if ((inbuf.seq > 0) &&
		(inbuf.seq >= next_tick)) {
		Output(" %d", next_tick);
		next_tick = (inbuf.seq + tick_interval) /
		    tick_interval * tick_interval;
	    }
	    if ((ret=Recv(&inbuf,sizeof(inbuf))) < 0) {
				/* timed out, no reply */
		if (stop_on_error) {
		    fprintf(stderr,
			    "\nMissed a packet (seq: %d)\n",
			    outbuf.seq);
		    PrintResults();
		    exit(-1);
		}

		if (ret == -1)
		    Output("X"); /* timeout */
		else if (ret == -2)
		    Output("R"); /* conn refused */
		else
		    Output("?");

		if (burst_size == 1)
		    pt[outbuf.seq].recv_t = TIMEOUT;
		continue;
	    }
	    if (pt[inbuf.seq].send_t == NULLTIME) {
		Error("bad sequence, received seq %d not yet sent\n",
		      inbuf.seq);
		continue;
	    }
	    if (pt[inbuf.seq].recv_t == TIMEOUT) {
				/* we already gave up on this one */
		++late_receives;
		continue;
	    } else if (pt[inbuf.seq].recv_t != NULLTIME) {
		Error("duplicate response, seq %d\n",
		      inbuf.seq);
		continue;
	    }
	    pt[inbuf.seq].recv_t = gettime();
	    ++num_packets_rcvd;
	    if (verify && !VerifyBuf(&inbuf,data_size)) {
		if (stop_on_error)
		    Error("bad data received in packet %d\n",
			  inbuf.seq);
	    }
	}
		
	if (num_packets_sent >= num_packets)
	    break;
    }
    PrintResults();

    exit(0);
}



static void
PrintResults(void)
{
    double elaps_t;
    double min_t;
    double max_t;
    double total_t;
    int i;

    /* look up the packet stats */
    min_t = 999.0;
    max_t = 0.0;
    total_t = 0.0;
    for (i=1; i <= num_packets; ++i) {
	if ((pt[i].send_t == NULLTIME) ||
	    (pt[i].recv_t == NULLTIME) ||
	    (pt[i].recv_t == TIMEOUT))
	    continue;
		
	elaps_t = pt[i].recv_t - pt[i].send_t;
	total_t += elaps_t;

	if (min_t > elaps_t)
	    min_t = elaps_t;
	    
	if (max_t < elaps_t)
	    max_t = elaps_t;
    }

    if (num_packets_rcvd == 0)
	return;

    Output("\n\ntime spent waiting for echos to return (in milliseconds):\n");

    Output("# sent  # rcvd  # late       total        min       max       avg\n");
    Output("------  ------  ------  -----------  --------  --------  --------\n");

    Output("%6d  %6d  %6d  %11.3f  %8.3f  %8.3f  %8.3f \n",
	   num_packets_sent,
	   num_packets_rcvd,
	   late_receives,
	   total_t, min_t, max_t,
	   total_t / num_packets_rcvd);
    Output("%.2f%% packet loss\n",
	   (float) 100 * (num_packets_sent - num_packets_rcvd) / 
	   num_packets_sent);
}


static void
sighandle(int sig)
{
    PrintResults();
    exit(-1);
}



/* return floating point time in milliseconds since first call */
double gettime(void)
{
    register double tf;
    struct timeval  tv;
    struct timezone tzp;
    static struct timeval first_secs = {0,0};

    if (first_secs.tv_sec == 0)
	gettimeofday(&first_secs,0);


    gettimeofday(&tv,&tzp);
    tv.tv_sec -= first_secs.tv_sec;

    tf =  (double) (tv.tv_sec * 1000);
    tf += (double) (tv.tv_usec / 1000.0);

    return(tf);
}



char  *gl_host;
int   gl_port;
int   gl_fd_in;
int   gl_fd_out;


static void
Open(
    char *host, char *service)
{
    struct servent servent;
    struct servent *pservent;

    if ((pservent = getservbyname(service,"udp")) == NULL) {
	int port = atoi(service);
	servent.s_port = htonl(port);
	pservent = &servent;
	if (port == 0) {
	    perror(service);
	    exit(-1);
	}
    }

//    if (gethostbyname (host) == NULL)
//	Error("unknown host: %s", host);

    gl_port = pservent->s_port;
    gl_host = host;

    gl_fd_in = gl_fd_out = GetUdpPort(ip_version);
}


static void
Send(void *buf, int len)
{
    static int af;
    static struct sockaddr_in  sa4;
    static struct sockaddr_in6 sa6;
    static int sa_len = 0;
    static char *psa=NULL;
    static struct hostent *phe = NULL;

    // make up the SA, if we haven't yet
    if (psa == NULL) {
	if (ip_version == 4) {
	    af = AF_INET;

	    if ((phe = gethostbyname (gl_host)) == NULL)
		SysError("unknown IPv4 host: %s", gl_host);

	    sa4.sin_addr = *( (struct in_addr *) (phe->h_addr));
	    sa4.sin_family = af;
	    sa4.sin_port = gl_port; /* already in NBO */
	    sa_len = sizeof(sa4);
	    psa = (void *)&sa4;
	} else if (ip_version == 6) {
	    static struct in6_addr addr6;
	    char *paddr;
	    af = AF_INET6;

	    // see if it's numeric first
	    if (inet_pton(af,host,&addr6) == 1) {
			paddr = (char *)&addr6;
	    } else {
			// better be something we can map with DNS, then!
			if ((phe = gethostbyname (gl_host)) == NULL)
				SysError("unknown IPv6 host: %s", gl_host);
			paddr = phe->h_addr;
	    }

	    memcpy(&sa6.sin6_addr,paddr,sizeof(struct in6_addr));
	    sa6.sin6_family = af;
	    sa6.sin6_port = gl_port; /* already in NBO */
	    sa_len = sizeof(sa6);
	    psa = (void *)&sa6;
	} else {
	    fprintf(stderr,
		    "Wow, IP version %d, never thought I'd live to see that!\n",
		    ip_version);
	    exit(1);
	}
    }

    if (sendto(gl_fd_out,buf,len,0,(void *)psa,sa_len) != len)
	SysError("sendto");
}


static int
Recv(void *buf, int len)
{
    fd_set in_fds;
    fd_set out_fds;
    struct timeval tv;
    int stat;

    FD_ZERO(&in_fds);
    FD_ZERO(&out_fds);
    FD_SET(gl_fd_in,&in_fds);
    tv.tv_sec  = max_wait_msecs / 1000;
    tv.tv_usec = (max_wait_msecs % 1000) * 1000;

    if ((stat = select(NFDBITS,&in_fds,&out_fds,0,&tv)) <=0) {
	if (stat != 0) {
	    SysError("select");
	}
	return(-1);
    }

    /* read the packet */
    if (read(gl_fd_in,buf,len) <= 0) {
	perror("read");
	if (errno == ECONNREFUSED) {
	    return(-2);
	}
	SysError("read");
    }
    return(0);
}


static void
usage(void)
{
    fprintf(stderr,"Udpping version 2.2 - Tue May 27, 2008\n");

    fprintf(stderr,
	    "usage: %s [-s] [-4|6] [-p N] [-P port] [-m MSECS] [-B N] [-b N] [-t N] [-c] [-v] host\n",
	    program);
    fprintf(stderr,
	    "       -s  stop when you lose a packet\n");
    fprintf(stderr,
	    "       -p  number of packets to send, default %d\n",
	    DEFAULT_NUM_PACKETS);
    fprintf(stderr,
	    "       -b  number of bytes per packet, default %d\n",
	    DEFAULT_DATA_SIZE);
    fprintf(stderr,
	    "       -B  number of packets per write (burst), default %d\n",
	    DEFAULT_BURST_SIZE);
    fprintf(stderr,
	    "       -m  packet timeout in milliseconds, default %d\n",
	    DEFAULT_MAX_WAIT_MSECS);
    fprintf(stderr,
	    "       -t  distance between 'ticks', default is %d\n",
	    DEFAULT_TICK_INTERVAL);
    fprintf(stderr,
	    "       -P  port (or service name), default is port 7\n");
    fprintf(stderr,
	    "       -v  verify data on receipt\n");
    exit(-1);
}


static void
InitBuf(struct echobuf *pbuf)
{
    int i;
    pbuf->seq = 0;
    for (i=0; i < MAX_DATA; ++i)
	pbuf->data[i] = (unsigned char) i;
}


static int
VerifyBuf(struct echobuf *pbuf, int len)
{
    int i;

    for (i=0; i < len; ++i)
	if (pbuf->data[i] != outbuf.data[i]) {
	    Output("\nError in response %d at location %d, saw %x, wanted %x\n",
		   pbuf->seq, i, outbuf.data[i],pbuf->data[i]);
	    return(FALSE);
	}
    return(TRUE);
}
