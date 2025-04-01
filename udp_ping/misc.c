/* 
 * misc.c
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
#include <stdarg.h>
#include <string.h>


#include "udpping.h"

extern char *program;


/*
 * ====================================================================
 * SysError - an unexpected error was detected in a system call
 *
 *  FATAL
 *
 * ====================================================================
 */
/*VARARGS1*/
void
SysError(
    char *format,
    ...)
{
    va_list ap;

    (void) fprintf(stderr,"\n%s: SYSERROR: ", program);

    va_start(ap,format);
    (void) vfprintf(stderr,format,ap);
    va_end(ap);

    (void) fprintf(stderr," (%s)\n", strerror(errno));
    exit(-1);
}



/*
 * ====================================================================
 * Error - an unexpected error was detected 
 *
 *  FATAL
 *
 * ====================================================================
 */
/*VARARGS1*/
void
Error(
    char *format,
    ...)
{
    va_list ap;

    (void) fprintf(stderr,"\n%s: ", program);

    va_start(ap,format);
    (void) vfprintf(stderr,format,ap);
    va_end(ap);

    (void) fprintf(stderr,"\n");
    exit(-1);
}



/*
 * ====================================================================
 * Output - normal output method
 *  tries not to wrap around lines
 * ====================================================================
 */
/*VARARGS1*/
void
Output(
    char *format,
    ...)
{
    static char outbuf[1000];
    static int llength = 0;
    int len;
    char *pch;
    va_list ap;

    va_start(ap,format);
    vsprintf(outbuf,format,ap);
    va_end(ap);

    len = strlen(outbuf);

    if (llength != 0 && llength + len > 75) {
	printf("\n");
	llength = 0;
    }

    fwrite(outbuf,len,1,stdout);
    fflush(stdout);
    llength += len;

    if ((pch = strrchr(outbuf,'\n')) != NULL)  /* rindex */
	llength = len - (int) (pch - outbuf) - 1;
}
