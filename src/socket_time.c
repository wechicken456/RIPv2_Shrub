/* socket.c - really quick client socket example		*/
/* Shawn Ostermann - March 26, 2025			*/
/* since it's just an example, there is no error checking (which*/
/* makes it useless in the real world!!!)			*/
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>


int main(int argc, char *argv[])
{
    char *remote_host = NULL;
    struct sockaddr_in sin;	/* an Internet endpoint address */
    char buf[128];		    /* buffer for sending */
    time_t tbuf; 		    /* buffer for reading */
    int s;			        /* socket descriptor */

    if (argc != 2) {
        fprintf(stderr,"Usage: %s IP address (try 132.235.1.1)\n", argv[0]);
        exit(1);
    }
    remote_host = argv[1];

    /* Allocate a socket */
    s = socket(PF_INET,		    /* Internet Protocol Family */
            SOCK_DGRAM,	        /* Datagram connection */
	        IPPROTO_UDP);	    /* ... specifically, UDP */
    if (s == -1) {
        perror("socket");
        exit(2);
    }
    /* connect to prime's time of day service */
    memset(&sin, 0, sizeof(sin)); /* erase address struct */
    sin.sin_family = AF_INET;	  /* Internet Address Family */
    sin.sin_port = htons(37);	  /* time port - RFC 868 */
    sin.sin_addr.s_addr = inet_addr(remote_host); 
    if (connect(s, (struct sockaddr *)&sin, sizeof(sin)) == -1) {
        perror("connect");
        exit(2);
    }

    /* send an empty datagram as a request */
    sprintf(buf,"What time is it???");
    if (send(s,buf,strlen(buf)+1,0) == -1) {
        perror("send");
        exit(2);
    }

    /* read the time */
    if (read(s,&tbuf,sizeof(tbuf)) == -1) {
        perror("read");
        exit(2);
    }
    close(s);

    /* ... and print it out! */
    printf("The time on %s is 0x%08x\n", remote_host, (uint32_t)tbuf);

    exit(0);
}
