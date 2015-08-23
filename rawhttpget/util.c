#include "rawhttpget.h"

void url_to_addr(char *url, char *addr, size_t size){
    struct hostent *h_ent;
    if ((h_ent = gethostbyname(url)) == NULL) {
        perror("Error in resolving host name\n");
        exit(1);
    }
    inet_ntop(AF_INET, h_ent->h_addr_list[0], addr, size);
}

int gen_port_num(){
    struct timeval cur_time;
    gettimeofday(&cur_time, NULL);
    int useconds = cur_time.tv_usec;
    return useconds % (RECV_PORT_END - RECV_PORT_START) + RECV_PORT_START;
}

// checksum calculation
unsigned short checksum(unsigned short *ptr, int nbytes){
    register long sum = 0;
    unsigned short oddbyte;
    register short answer = 0;

    while (nbytes>1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1){
        oddbyte = 0;
        *((u_char*)&oddbyte) = *(u_char*)ptr;
        sum += oddbyte;
    }

    sum = (sum>>16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (short)~sum;

    return answer;
}

int proc_http(char *buf, size_t len){
    int i = 0;    
    int doc_len = 0, j = 0;
    while (i < len){
        if (buf[i] != 'C') {
            i ++;
            continue;
        }
        if (strncmp(buf+i, "Content-Length", 14) == 0){
            j = i + 16;
            break;
        }
    }
    while (buf[j] >= '0' && buf[j] <= '9'){
        doc_len *= 10;
        doc_len += (buf[j] - '0');
        j ++;
    }
    i = j;
    while (i <= len - 4){
        if (strncmp(buf+i, "\r\n\r\n", 4) == 0 && (i == len-4 || buf[i+4] != '\r')){
            break;
        }
        i ++;
    }
    return doc_len + i + 4;
}
