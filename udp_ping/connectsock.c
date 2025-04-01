/* connectsock.c - connectsock */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>

#include "udpping.h"

#ifndef INADDR_NONE
#define INADDR_NONE     0xffffffff
#endif  /* INADDR_NONE */


/*------------------------------------------------------------------------
 * connectUDP - connect to a specified UDP service on a specified host
 *------------------------------------------------------------------------
 */
int
connectUDP(
    char    *host,          /* name of host to which connection is desired  */
    char    *service)       /* service associated with the desired port     */
{
    return connectsock(host, service, "udp");
}



/*------------------------------------------------------------------------
 * connectsock - allocate & connect a socket using TCP or UDP
 *------------------------------------------------------------------------
 */
int
connectsock(
    char    *host,          /* name of host to which connection is desired  */
    char    *service,       /* service associated with the desired port     */
    char    *protocol)      /* name of protocol to use ("tcp" or "udp")     */
{
    struct hostent  *phe;   /* pointer to host information entry    */
    struct servent  *pse;   /* pointer to service information entry */
    struct protoent *ppe;   /* pointer to protocol information entry*/
    struct sockaddr_in sin; /* an Internet endpoint address         */
    int     s, type;        /* socket descriptor and socket type    */


    memset((char *)&sin, 0, sizeof(sin)); /* bzero */
    sin.sin_family = AF_INET;

    /* Map service name to port number */
    if ((pse = getservbyname(service, protocol)) != NULL)
	sin.sin_port = pse->s_port;
    else if ( (sin.sin_port = htons((u_short)atoi(service))) == 0 )
	Error("can't get \"%s\" service entry\n", service);

    /* Map host name to IP address, allowing for dotted decimal */
    if ((phe = gethostbyname(host)) != NULL)
	memcpy((char *)&sin.sin_addr, phe->h_addr, phe->h_length);
    else if ( (sin.sin_addr.s_addr = inet_addr(host)) == INADDR_NONE )
	Error("can't get \"%s\" host entry\n", host);

    /* Map protocol name to protocol number */
    if ( (ppe = getprotobyname(protocol)) == 0)
	Error("can't get \"%s\" protocol entry\n", protocol);

    /* Use protocol to choose a socket type */
    if (strcmp(protocol, "udp") == 0)
	type = SOCK_DGRAM;
    else
	type = SOCK_STREAM;

    /* Allocate a socket */
    s = socket(PF_INET, type, ppe->p_proto);
    if (s < 0)
	SysError("can't create socket: %s\n", strerror(errno));

    /* Connect the socket */
    if (connect(s, (struct sockaddr *)&sin, sizeof(sin)) < 0)
	SysError("can't connect to %s.%s: %s\n", host, service,
		 strerror(errno));
    return s;
}
