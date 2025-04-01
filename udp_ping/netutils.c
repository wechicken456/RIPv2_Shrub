/* 
 * netutils.c - Handy routines for dealing with the network
 * 
 * Author:	Tim Korb/Shawn Ostermann/Jim Griffioen
 * 		Dept. of Computer Sciences
 * 		Purdue University
 * Date:	Thu Jun  9 21:32:25 1988
 *
 * Copyright (c) 1988 Tim Korb/Shawn Ostermann/Jim Griffioen
 */

#include <stdio.h>
#include <errno.h>
#include <sys/time.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include "udpping.h"


extern int errno;


/*
 *---------------------------------------------------------------------------  
 * GetUdpPort() -- allocate a local UDP port.
 *--------------------------------------------------------------------------- 
 */

int GetUdpPort(int ip_version)

{
    int fd;
    int af;
    struct sockaddr_in  sa4;
    struct sockaddr_in6 sa6;
    char *psa;
    int sa_len;

    if (ip_version == 4) {
		af = AF_INET;
		sa4.sin_family = af;
		sa4.sin_port = 0;
		sa4.sin_addr.s_addr = INADDR_ANY;
		sa_len = sizeof(sa4);
		psa = (void *)&sa4;
    } else if (ip_version == 6) {
		af = AF_INET6;
		sa6.sin6_family = af;
		sa6.sin6_port = 0;
		memcpy(&sa6.sin6_addr, &in6addr_any, sizeof(struct in6_addr));
		sa_len = sizeof(sa6);
		psa = (void *)&sa6;
    } else {
		fprintf(stderr,
			"Wow, IP version %d, never thought I'd live to see that!\n",
			ip_version);
		exit(1);
    }

    if ((fd = socket (af, SOCK_DGRAM, 0)) < 0)
	SysError("socket");

    if (bind (fd, (struct sockaddr *) psa, sa_len) == -1)
	SysError("bind");
    
    return(fd);
}
