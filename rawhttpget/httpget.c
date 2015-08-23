#include "rawhttpget.h"

int sock_send, sock_recv;
int connected;
int all_get;
unsigned int start_seq_num;
unsigned int expected_seq;
unsigned int seq_num;
unsigned int last_seq;
int passive_fin;
int fd;
//char src_ip[ADDR_BUF_SIZE];
struct sockaddr_in sin_send;
struct sockaddr_in sin_recv;
pseudo_header ph_send;
pseudo_header ph_recv;
void create_sockets(){
    int one = 1;
    if (0 > (sock_send = socket (AF_INET, SOCK_RAW, IPPROTO_RAW))){
        perror("Fail to create send socket\n");
        exit(1);
    }
    if (0 > (sock_recv = socket(AF_INET, SOCK_RAW, IPPROTO_TCP))){
        perror("Fail to create receive socket\n");
        exit(1);
    }
    if (setsockopt (sock_recv, IPPROTO_IP, IP_HDRINCL, &one, sizeof (one)) < 0){
        perror("Error setting IP_HDRINCL\n");
        exit(0);
    }
}


void close_sockets(){
    close(sock_send);
    close(sock_recv);
}

// get the ip address of the local machine

// Initialize socket address for sending packets
void ini_send_addr(char *addr){
    memset(&sin_send, 0, sizeof(sin_send));
    sin_send.sin_family = AF_INET;
    sin_send.sin_port = htons(HTTP_PORT);
    sin_send.sin_addr.s_addr = inet_addr(addr);
}

// Initialize socket address for receiving packets
int ini_recv_addr(){
    sin_recv.sin_family = AF_INET;
    sin_recv.sin_addr.s_addr = INADDR_ANY;
    int recv_port= gen_port_num();
    sin_recv.sin_port = htons(recv_port);
    if (bind(sock_recv, (struct sockaddr *)&sin_recv, sizeof(sin_recv)) >= 0){
        return recv_port;
    }
    perror("Error finding a port.\n");
    exit(1);
    return -1;
}


void conn_server(char *src_ip, char *dst_ip, char *path, int recv_port){
    // build syn packet
    char buf[10000];
    char ack_buf[10000];
    size_t len, sent, recv_size, http_req_size;
    struct iphdr *iph;
    struct tcphdr *tcph;
    len = build_syn_packet(buf, 2000, src_ip, dst_ip, recv_port, start_seq_num);
    sent = sendto(sock_send, buf, len, 0, (struct sockaddr *)&sin_send, sizeof(sin_send));
    printf("SYN packet sent, size: %u\n", sent);
    // receive ack 
    while (connected != 1){
        recv_size = recv(sock_recv, buf, sizeof(buf), 0);
        if (recv_size < IP_HDR_SIZE + TCP_HDR_SIZE) {
            continue;
        }
        iph = (struct iphdr *)buf;
        tcph = (struct tcphdr *)(buf + IP_HDR_SIZE);
        if (iph->saddr != inet_addr(dst_ip) && tcph->source != htons(HTTP_PORT) && ntohl(tcph->dest) != recv_port){
            continue;
        }
        printf("Received: %u\n", recv_size);
        if (tcph->syn == 1 && tcph->ack == 1){
            seq_num = start_seq_num + 1;
            len = build_ack(ack_buf, buf, recv_port, src_ip, dst_ip, seq_num);
            sendto(sock_send, ack_buf, len, 0, (struct sockaddr *)&sin_send, sizeof(sin_send));
            printf("Ack replied for connection\n");
            len = build_http_req(ack_buf, buf, 10000, src_ip, dst_ip, recv_port, path, seq_num);
            http_req_size = len - IP_HDR_SIZE - TCP_HDR_SIZE;
            sendto(sock_send, ack_buf, len, 0, (struct sockaddr *)&sin_send, sizeof(sin_send));
            continue;
        }
        if (tcph->ack == 1) {
            if (ntohl(tcph->ack_seq) == seq_num + http_req_size){
                seq_num += http_req_size;
                expected_seq = ntohl(tcph->seq);
                connected = 1;
            }
        }
    }
}


void receive_data(char *src_ip, char *dst_ip, char *path, int recv_port){
    // build syn packet
    char buf[10000];
    char ack_buf[10000];
    size_t len, recv_size, data_size;
    struct iphdr *iph;
    struct tcphdr *tcph;
    int first = 1;
    while (all_get == 0){
        memset(buf, 0, sizeof(buf));
        recv_size = recv(sock_recv, buf, sizeof(buf), 0);
        if (recv_size < IP_HDR_SIZE + TCP_HDR_SIZE) {
            continue;
        }
        iph = (struct iphdr *)buf;
        tcph = (struct tcphdr *)(buf + IP_HDR_SIZE);
        if (iph->saddr != inet_addr(dst_ip) && tcph->source != htons(HTTP_PORT) && ntohl(tcph->dest) != recv_port){
            continue;
        }
        data_size = (recv_size - IP_HDR_SIZE - TCP_HDR_SIZE);
        if (tcph->ack == 1 && tcph->syn == 0 && tcph->fin == 0 && tcph->rst == 0) {
            if (ntohl(tcph->seq) > expected_seq){
                continue;
            }
            if (ntohl(tcph->seq) == expected_seq){
                if (first == 1){
                    int doc_size = proc_http(buf+IP_HDR_SIZE+TCP_HDR_SIZE, data_size);
                    last_seq = ntohl(tcph->seq) + doc_size;
                    printf("doc size: %d\n", doc_size);
                    first = 0;
                }
                expected_seq += data_size;
                write(fd, buf+IP_HDR_SIZE+TCP_HDR_SIZE, data_size);
            }
            len = build_ack(ack_buf, buf, recv_port, src_ip, dst_ip, seq_num);
            sendto(sock_send, ack_buf, len, 0, (struct sockaddr *)&sin_send, sizeof(sin_send));
        }
        if(ntohl(tcph->seq) + data_size == last_seq){
            printf("All data received\n");
            return;
        }
        if (tcph->fin == 1) {
            passive_fin = 1;
        }
    }
}

void disconnect(char *src_ip, char *dst_ip, char *path, int recv_port){
    // build fin packet
    char buf[10000];
    char ack_buf[10000];
    size_t len, sent, recv_size;
    struct iphdr *iph;
    struct tcphdr *tcph;
    if (passive_fin == 0){
        len = build_fin_packet(buf, 2000, src_ip, dst_ip, recv_port, seq_num, expected_seq);
        sent = sendto(sock_send, buf, len, 0, (struct sockaddr *)&sin_send, sizeof(sin_send));
        printf("FIN packet sent, size: %u\n", sent);
    }
    // receive ack 
    while (connected == 1){
        recv_size = recv(sock_recv, buf, sizeof(buf), 0);
        if (recv_size < IP_HDR_SIZE + TCP_HDR_SIZE) {
            continue;
        }
        iph = (struct iphdr *)buf;
        tcph = (struct tcphdr *)(buf + IP_HDR_SIZE);
        if (iph->saddr != inet_addr(dst_ip) && tcph->source != htons(HTTP_PORT) && ntohl(tcph->dest) != recv_port){
            continue;
        }
        if (tcph->fin == 1 && tcph->ack == 1){
            seq_num += 1;
            len = build_ack(ack_buf, buf, recv_port, src_ip, dst_ip, seq_num);
            sendto(sock_send, ack_buf, len, 0, (struct sockaddr *)&sin_send, sizeof(sin_send));
            return;
        }
    }
}

int main(int argc, char **argv){
    if (argc != 5){
        printf("Wrong args\n");
        exit(0);
    }
    fd = open(argv[4], O_WRONLY|O_CREAT);
    if (fd == -1){
        printf("Error opening log file\n");
        exit(1);
    }
    connected = 0;
    all_get = 0;
    start_seq_num = (unsigned int)rand();
    expected_seq = 0;
    last_seq = 0;
    passive_fin = 0;
    create_sockets();
    ini_send_addr(argv[2]);
    int recv_port = ini_recv_addr();
    conn_server(argv[1], argv[2], argv[3], recv_port);
    printf("Connection established!\n");
    receive_data(argv[1], argv[2], argv[3], recv_port);
    disconnect(argv[1], argv[2], argv[3], recv_port);
    close_sockets();
    close(fd);
    return 0;
}
