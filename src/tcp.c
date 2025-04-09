#include "tcp.h"

void print_tcp_flags(uint8_t flags) {
    printf("\t\tFlags:\t");
    for (int i = 0 ; i < 6; i++) {
        if (flags & (1 << i)) {
            printf("%c", tcp_flag_string[i]);
        } else {
            printf("-");
        }
    }
    puts("");
}

void print_tcp(struct tcp_hdr *tcp_segment) {
        printf("\tTCP:\tSport:\t%u\n", *(uint16_t*)tcp_segment->src_port);
    printf("\t\tDport:\t%u\n", *(uint16_t*)tcp_segment->dst_port);
    print_tcp_flags(tcp_segment->flags);
    printf("\t\tSeq:\t%u\n", *(uint32_t*)tcp_segment->sent_seq);
    printf("\t\tACK:\t%u\n", *(uint32_t*)tcp_segment->recv_ack);
    printf("\t\tWin:\t%u\n", *(uint16_t*)tcp_segment->rx_win);
    printf("\t\tCSum:\t%u\n", *(uint16_t*)tcp_segment->cksum);
}

void process_tcp(struct tcp_hdr *tcp_segment) {


    reverse_assign(&(tcp_segment->src_port), sizeof(tcp_segment->src_port));
    reverse_assign(&(tcp_segment->dst_port), sizeof(tcp_segment->dst_port));

    reverse_assign(&(tcp_segment->flags), sizeof(tcp_segment->flags));
    reverse_assign(&(tcp_segment->rx_win), sizeof(tcp_segment->rx_win));
    reverse_assign(&(tcp_segment->sent_seq), sizeof(tcp_segment->sent_seq));
    reverse_assign(&(tcp_segment->recv_ack), sizeof(tcp_segment->recv_ack));
    reverse_assign(&(tcp_segment->cksum), sizeof(tcp_segment->cksum));


    print_tcp(tcp_segment);

}