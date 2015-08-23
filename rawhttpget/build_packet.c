#include "rawhttpget.h"

void ini_ph_send(char *pseudogram, size_t data_len, char *src_ip, char *dst_ip){
    pseudo_header *ph_send = (pseudo_header *)pseudogram;
    ph_send->src_addr = inet_addr(src_ip);
    ph_send->dst_addr = inet_addr(dst_ip);
    ph_send->zeros = htons(0);
    ph_send->protocol = IPPROTO_TCP;
    ph_send->tcp_len = htons(TCP_HDR_SIZE + data_len);
}

void fill_ip_hdr(char *buf, char *src_ip, char *dst_ip, size_t data_len){
    struct iphdr *iph = (struct iphdr *) buf;
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(IP_HDR_SIZE + TCP_HDR_SIZE + data_len);
    iph->id = htons(rand()%65535);
    iph->frag_off = 0;//|= 0x0040;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = inet_addr(src_ip);
    iph->daddr = inet_addr(dst_ip);
    iph->check = 0;
    iph->check = checksum((unsigned short *)buf, IP_HDR_SIZE + TCP_HDR_SIZE + data_len);
}

size_t build_syn_packet(char *buf, size_t len, char *src_ip, char *dst_ip, int recv_port, int seq_num){
    memset(buf, 0, len);
    fill_ip_hdr(buf, src_ip, dst_ip, 0);
    //printf("Start constructing packet\n");
    struct tcphdr *tcph = (struct tcphdr *)(buf + sizeof(struct iphdr));
    tcph->source = htons(recv_port);
    tcph->dest = htons(HTTP_PORT);
    tcph->seq = htonl(seq_num);
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->fin = 0;
    tcph->syn = 1;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 0;
    tcph->window = htons(MAX_TCP_WIN_SIZE); // Maximum window size
    tcph->check = 0;
    tcph->urg_ptr = 0;
    int psize = sizeof(pseudo_header) + TCP_HDR_SIZE;
    char *pseudogram = malloc(psize);
    ini_ph_send(pseudogram, 0, src_ip, dst_ip);
    memcpy(pseudogram + sizeof(pseudo_header), tcph, TCP_HDR_SIZE);
    tcph->check = checksum((unsigned short *)pseudogram, psize);
    free(pseudogram);
    return IP_HDR_SIZE + TCP_HDR_SIZE;
}

size_t build_fin_packet(char *buf, size_t len, char *src_ip, char *dst_ip, int recv_port, int seq_num, int ack_num){
    memset(buf, 0, len);
    fill_ip_hdr(buf, src_ip, dst_ip, 0);
    //printf("Start constructing packet\n");
    struct tcphdr *tcph = (struct tcphdr *)(buf + sizeof(struct iphdr));
    tcph->source = htons(recv_port);
    tcph->dest = htons(HTTP_PORT);
    tcph->seq = htonl(seq_num);
    tcph->ack_seq = htonl(ack_num);
    tcph->doff = 5;
    tcph->fin = 1;
    tcph->syn = 0;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 1;
    tcph->urg = 0;
    tcph->window = htons(MAX_TCP_WIN_SIZE); // Maximum window size
    tcph->check = 0;
    tcph->urg_ptr = 0;
    int psize = sizeof(pseudo_header) + TCP_HDR_SIZE;
    char *pseudogram = malloc(psize);
    ini_ph_send(pseudogram, 0, src_ip, dst_ip);
    memcpy(pseudogram + sizeof(pseudo_header), tcph, TCP_HDR_SIZE);
    tcph->check = checksum((unsigned short *)pseudogram, psize);
    free(pseudogram);
    return IP_HDR_SIZE + TCP_HDR_SIZE;
}

size_t build_ack(char *ack_buf, char *recv_buf, int recv_port, char *src_ip, char *dst_ip, int seq_num){
    memset(ack_buf, 0, IP_HDR_SIZE + TCP_HDR_SIZE);
    fill_ip_hdr(ack_buf, src_ip, dst_ip, 0);
    struct tcphdr *tcph = (struct tcphdr *)(ack_buf + IP_HDR_SIZE);
    struct iphdr *iph = (struct iphdr *)recv_buf;
    struct tcphdr *tcph_recv = (struct tcphdr *)(recv_buf + IP_HDR_SIZE);
    u_int32_t ack_seq = 0;
    size_t data_len = ntohs(iph->tot_len) - IP_HDR_SIZE - TCP_HDR_SIZE;
    if (tcph_recv->syn == 1 || tcph_recv->fin == 1){
        ack_seq = htonl(ntohl(tcph_recv->seq) + 1);
    }
    else {
        ack_seq = htonl(ntohl(tcph_recv->seq) + data_len);
    }
    tcph->source = htons(recv_port);
    tcph->dest = htons(80);
    tcph->seq = htonl(seq_num);
    tcph->ack_seq = ack_seq;
    tcph->doff = 5;
    tcph->fin = 0;
    tcph->syn = 0;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 1;
    tcph->urg = 0;
    tcph->window = htons(MAX_TCP_WIN_SIZE); // Maximum window size
    tcph->check = 0;
    int psize = sizeof(pseudo_header) + TCP_HDR_SIZE;
    char *pseudogram = malloc(psize);
    ini_ph_send(pseudogram, 0, src_ip, dst_ip);
    memcpy(pseudogram + sizeof(pseudo_header), tcph, TCP_HDR_SIZE);
    tcph->check = checksum((unsigned short *)pseudogram, psize);
    free(pseudogram);
    return IP_HDR_SIZE + TCP_HDR_SIZE;    
}

size_t build_http_req(char *buf, char *recv_buf, size_t len, char *src_ip, char *dst_ip, int recv_port, char *path, int seq_num){
    memset(buf, 0, len);
    char *req_ptr = buf + IP_HDR_SIZE + TCP_HDR_SIZE;
    sprintf(req_ptr, "GET %s HTTP/1.1\r\nHost: www.ccs.neu.edu\r\n\r\n\r\n", path);

    size_t data_len = strlen(buf + IP_HDR_SIZE + TCP_HDR_SIZE);
    printf("Http req length: %d\n", data_len);
    fill_ip_hdr(buf, src_ip, dst_ip, data_len);
    //printf("Start constructing packet\n");
    struct tcphdr *tcph = (struct tcphdr *)(buf + sizeof(struct iphdr));
    struct tcphdr *tcph_recv = (struct tcphdr *)(recv_buf + IP_HDR_SIZE);
    u_int32_t ack_seq = 0;
    ack_seq = htonl(ntohl(tcph_recv->seq) + 1);
    tcph->source = htons(recv_port);
    tcph->dest = htons(HTTP_PORT);
    tcph->seq = htonl(seq_num);
    tcph->ack_seq = ack_seq;
    tcph->doff = 5;
    tcph->fin = 0;
    tcph->syn = 0;
    tcph->rst = 0;
    tcph->psh = 1;
    tcph->ack = 1;
    tcph->urg = 0;
    tcph->window = htons(1840); // Maximum window size
    tcph->check = 0;
    tcph->urg_ptr = 0;
    
    int psize = sizeof(pseudo_header) + TCP_HDR_SIZE + data_len;
    char *pseudogram = malloc(psize);
    ini_ph_send(pseudogram, data_len, src_ip, dst_ip);
    memcpy(pseudogram + sizeof(pseudo_header), tcph, TCP_HDR_SIZE + data_len);
    tcph->check = checksum((unsigned short *)pseudogram, psize);
    free(pseudogram);
    printf("Build packet successfully\n");
    return IP_HDR_SIZE + TCP_HDR_SIZE + data_len;
}
