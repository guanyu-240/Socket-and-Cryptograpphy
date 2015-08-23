#ifndef _RAWHTTPGET_H_
#define _RWAHTTPGET_H_

#include <stdio.h> 
#include <string.h> 
#include <sys/socket.h>    
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h> 
#include <errno.h> 
#include <netinet/tcp.h>   
#include <netinet/ip.h>    
#include <sys/ioctl.h>
#include <net/if.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>

#define HTTP_PORT 80
#define ADDR_BUF_SIZE 100
#define RECV_PORT_START 30000 
#define RECV_PORT_END 40000
#define MAX_TCP_WIN_SIZE 640 
#define IP_HDR_SIZE sizeof(struct iphdr)
#define TCP_HDR_SIZE  sizeof(struct tcphdr)
#define SYN 1
#define FIN 2

typedef struct tcpchecksum_pseudo_header{
    u_int32_t src_addr;
    u_int32_t dst_addr;
    u_int8_t zeros;
    u_int8_t protocol;
    u_int16_t tcp_len;
}pseudo_header;


extern void url_to_addr(char *url, char *addr, size_t size);
extern unsigned short checksum(unsigned short *ptr, int nbytes);
extern int gen_port_num();
extern int proc_http(char *buf, size_t len);

extern size_t build_syn_packet(char *buf, size_t len, char *src_ip, char *dst_ip, int recv_port, int seq_num);
extern size_t build_ack(char *ack_buf, char *recv_buf, int recv_port, char *src_ip, char *dst_ip, int seq_num);
extern size_t build_http_req(char *buf, char *recv_buf, size_t len, char *src_ip, char *dst_ip, int recv_port, char *path, int seq_num);
extern size_t build_fin_packet(char *buf, size_t len, char *src_ip, char *dst_ip, int recv_port, int seq_num, int ack_num);
#endif
