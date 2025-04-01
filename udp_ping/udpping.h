/* 
 * udpping.h - udpping header file
 * 
 * Author:	Shawn Ostermann
 * 		Dept. of Computer Sciences
 * 		Purdue University
 * Date:	Fri Jan 31 16:35:25 1992
 *
 * Copyright (c) 1992 Shawn Ostermann
 */


#include <unistd.h>
#include <stdlib.h>
#include <errno.h>




#define VERSION "Version 3.2.0 -- Mon May 21, 2007"


/* useful constants */
#define TRUE 1
#define FALSE 0
#define NULLPTR	(void *) 0
#define NULLCH '\00'
#define NULLTIME -1.0
#define TIMEOUT -2.0
typedef char Bool;


/* global flags and etc... */
extern int num_hist_buckets;
extern int debug;
extern int ip_version;


/* configurations constants */
#define DEFAULT_NUM_PACKETS	1000
#define DEFAULT_DATA_SIZE	50
#define DEFAULT_BURST_SIZE	1
#define DEFAULT_TICK_INTERVAL	100
#define DEFAULT_MAX_WAIT_MSECS	500

#define MAX_DATA		10000
#define MAX_BURST		50

#define MAX_HIST_HEIGHT		45
#define DEFAULT_HIST_BUCKETS	50


/* global types */
struct packettime {
	double	send_t;
	double	recv_t;
};


/* routine declarations - misc */
void	SysError(char *,...);
void	Error(char *,...);
void	Output(char *,...);


/* routine declarations - connect */
int	connectUDP(char *,char *);
int	connectsock(char *,char *,char *);


/* routine declarations - hist */
void plot_hist(int, int, int, struct packettime *);


/* routine declarations - netutils */
char	*GetNetName();
int	ConnectUdp();
char	*sbHost();
char	*IaToSb();
int	ListenUdp();
int	Udp2Way();
int	GetUdpPort(int ip_version);
struct sockaddr_in *FdToRemoteSa();
struct sockaddr_in *FdToLocalSa();
