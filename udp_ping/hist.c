/* 
 * hist.c -- do the histogram stuff
 * 
 * Author:	Shawn Osteramnn
 * 		Dept. of Computer Sciences
 * 		Purdue University
 * Date:	Thu May 31 15:11:16 1990
 *
 * Copyright (c) 1990 Shawn Osteramnn
 */


#include <stdio.h>
#include <sys/types.h>
#include <sys/types.h>
#include <stdarg.h>
#include <math.h>
#include <string.h>


#include "udpping.h"


int num_hist_buckets = DEFAULT_HIST_BUCKETS;


void
plot_hist(
    int num_packets_sent,
    int min_rtt_usecs,
    int max_rtt_usecs,
    struct packettime *pt)
{
    int maxhist = 0;
    int bucket_ix;
    int i;
    int hist_bucket_size;
    int *phist = NULL;
    int j,num;
    float sf;
    int empty_lines = 0;


    /* how much data goes into each "bucket" */
    hist_bucket_size = (max_rtt_usecs - min_rtt_usecs) / (num_hist_buckets-1);


    if (0) {
	printf("min_rtt:          %d usecs\n", min_rtt_usecs);
	printf("max_rtt:          %d usecs\n", max_rtt_usecs);
	printf("num_hist_buckets: %d\n", num_hist_buckets);
	printf("hist_bucket_size: %d\n", hist_bucket_size);
    }


    /* allocate the hist bucket table */
    phist = (int *) malloc((1+num_hist_buckets) * sizeof(int));
    memset(phist,0,num_hist_buckets * sizeof(int));  /* bzero */


    /* count the packets in each bucket */
    while (1) {
	for (i=1; i <= num_packets_sent; ++i) {
	    double elaps_t = pt[i].recv_t;  /* already calculated in main */

	    bucket_ix = (int) (elaps_t-min_rtt_usecs) / hist_bucket_size;

	    if ((bucket_ix >= 0) && (bucket_ix < num_hist_buckets)) {
		++phist[bucket_ix];
	    }
	}

	/* see where the data ended up and re-scale FIXME */
	break;  /* good enough for now */
    }


    /* determine an appropriate scaling factor */
    for (i=0; i < num_hist_buckets; ++i) {
	if (phist[i] > maxhist)
	    maxhist = phist[i];
    }
    sf = (float) maxhist / MAX_HIST_HEIGHT;


    Output("\n\nPacket Arrival Time Histogram");
    Output(" (times in milliseconds, %.3f ms per bar)\n\n",
	   (double)hist_bucket_size/1000);
    for (i=0; i < num_hist_buckets; ++i) {
	char range[50];
	
	if (phist[i] == 0)
	    ++empty_lines;
	else
	    empty_lines = 0;
	if (phist[i] == 0) {
	    if (empty_lines == 1) {
		Output("      ... zero ...\n");
		continue;
	    } else if (empty_lines > 1)
		continue;
	}

	sprintf(range,"%.3f - %.3f",
	       (double) (i * hist_bucket_size + min_rtt_usecs) / 1000,
	       (double) ((i+1) * hist_bucket_size + min_rtt_usecs) / 1000);
			    
	Output("%18s (%4d) ", range, phist[i]);
	num = (float) phist[i] / sf;
	if (num < 1 && phist[i] > 0)
	    num = 1;
	for (j=0; j < num; ++j)
	    Output("=");
	Output("\n");
    }
}

