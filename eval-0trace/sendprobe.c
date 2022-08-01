
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <errno.h>

#include "types.h"

#define fatal(x) do { perror(x); exit(1); } while (0)

#define MAXDIST     64
#define MAXSEQDELTA 3

static _u8 synpacket[] = {

  /* IP HEADER */

  /* IHL    */ 0x45,
  /* ToS    */ 0x00,
  /* totlen */ 0x00, 0x28 + 2,
  /* ID     */ 0x00, 0x00,   /* id: [4] */
  /* offset */ 0x00, 0x00,
  /* TTL    */ 0xFF,         /* ttl: [8] */
  /* proto  */ 0x06,
  /* cksum */  0x00, 0x00,
  /* saddr */  0, 0, 0, 0,   /* src: [12] */
  /* daddr */  0, 0, 0, 0,   /* dst: [16] */

  /* TCP HEADER - [20] */

  /* sport */  0, 0,         /* sp: [20] */
  /* dport */  0, 0,	     /* dp: [22] */
  /* SEQ   */  0, 0, 0, 0,   /* seq: [24] */
  /* ACK   */  0, 0, 0, 0,   /* ack: [28] */
  /* doff  */  0x50,
  /* flags */  0x10,         /* ACK */
  /* wss   */  0xFF, 0xFF,
  /* cksum */  0x00, 0x00,   /* cksum: [36] */
  /* urg   */  0x00, 0x00,
  
  0, 0
  
};


_u16 simple_tcp_cksum(void) {
  _u32 sum = 26 + 2 /* tcp, len 20 */;
  _u8  i;
  _u8* p = synpacket + 20;

  for (i=0;i<10 + 1;i++) {
    sum += (*p << 8) + *(p+1);
    p+=2;
  }

  p = synpacket + 12;
  
  for (i=0;i<4;i++) {
    sum += (*p << 8) + *(p+1);
    p+=2;
  }

  return ~(sum + (sum >> 16));

}



int main(int argc, char** argv) {

  static struct sockaddr_in sain;
  _s32 sad,dad;
  _s32 sock, one = 1, i, d;
  _u16 sp,dp,ck;
  _u32 seq, ack, seq_o;

  if (argc - 7 || (sad=inet_addr(argv[1])) == INADDR_NONE || 
     (dad=inet_addr(argv[2])) == INADDR_NONE || !(sp=atoi(argv[3])) ||
     !(dp=atoi(argv[4])) || (sscanf(argv[5],"%lu",&seq_o) != 1) ||
     (sscanf(argv[6],"%lu",&ack) != 1)) {
    fprintf(stderr,"Usage: %s src_ip dst_ip sport dport seq ack\n",argv[0]);
    exit(1);
  }
  
  sock=socket(AF_INET,SOCK_RAW,IPPROTO_RAW);
  
  if (sock<0) fatal("socket");
  
  if (setsockopt(sock,IPPROTO_IP,IP_HDRINCL,(char *)&one,sizeof(one)))
    fatal("setsockopt");

  sain.sin_family = AF_INET;
  memcpy(&sain.sin_addr.s_addr,&dad,4);

  memcpy(synpacket+12,&sad,4);
  memcpy(synpacket+16,&dad,4);
  sp=htons(sp);
  memcpy(synpacket+20,&sp,2);
  dp=htons(dp);
  memcpy(synpacket+22,&dp,2);
  ack=htonl(ack);
  memcpy(synpacket+28,&ack,4);

  for (d=1;d<MAXSEQDELTA;d++) {

    seq=htonl(seq_o+d);
    memcpy(synpacket+24,&seq,4);
  
    for (i=0;i<MAXDIST;i++) {
  
      synpacket[4] = i;
      synpacket[8] = i;

      memset(synpacket+36,0,2);
      ck=simple_tcp_cksum();
      ck=htons(ck);
      memcpy(synpacket+36,&ck,2);

      if (sendto(sock,synpacket,sizeof(synpacket), 0,(struct sockaddr *)&sain,
        sizeof(struct sockaddr)) < 0) perror("sendto");
      usleep(1000);
    }

  }

  return 0;
    
}

