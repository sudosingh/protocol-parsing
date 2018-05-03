#include<stdlib.h>
#include<stdio.h>
#include<arpa/inet.h>
#include<stddef.h>
#include<stdint.h>
#include<unistd.h>


typedef struct{
	uint8_t dst[6];
	uint8_t src[6];
	uint16_t type;
}__attribute__((packed)) ETH_H;

typedef struct{
	uint8_t  ip_len;
	uint8_t field;
       	uint16_t total_len;
	uint16_t iden;
	uint8_t flag;
	uint8_t frag;
	uint8_t ttl;
	uint8_t prot;
	uint16_t check;
	uint32_t src_ip;
	uint32_t dst_ip;
}__attribute__((packed)) TCP;

typedef struct{
	uint16_t sport;
	uint16_t dport;
	uint32_t seq;
	uint32_t ack;
	uint8_t hlen;
	uint8_t flags;
	uint16_t win_size;
	uint32_t check_sum;
	uint32_t pointer;
}__attribute__((packed)) IP;	

typedef struct{
	ETH_H eth;
	TCP tcp;
	IP ip;
}packet;	

int main(int argc,char argv[]){
	FILE *fp;
	packet pkt;
	fp=fopen("tcp.hex","rb");
	if(!fp)
		exit(0);
	fread(&pkt,sizeof(packet),1,fp);
	printf("\nETHERNET II");
	printf("\n\tDestination");
	for(int i=0;i<6;i++) printf(":%01x",pkt.eth.dst[i]);
	printf("\n\tSource");
	for(int i=0;i<6;i++) printf(":%01x",pkt.eth.src[i]);
	printf("\n\tType: %02x",ntohs(pkt.eth.type));
	printf("\nINTERNET PROTOCOL");
	printf("\n\tVersion: %01x",(pkt.tcp.ip_len>>4));
	printf("\n\tHeader Length: %01x",(pkt.tcp.ip_len&0b00001111));
	printf("\n\tField: %01x",pkt.tcp.field);
	printf("\n\tTotal Length: %02x",ntohs(pkt.tcp.total_len));
	printf("\n\tIdentification: %d",ntohs(pkt.tcp.iden));
	printf("\n\tFLAGS: %01x",pkt.tcp.flag);
	printf("\n\tFragment Offset: %01x",pkt.tcp.frag);
	printf("\n\tTime to live: %d",pkt.tcp.ttl);
	printf("\n\tProtocol: %01x",pkt.tcp.prot);
	printf("\n\tHeader Checksum: %d",ntohs(pkt.tcp.check));
	struct in_addr src1,dst1;
	printf("\n\tSource IP: ");
	src1.s_addr=pkt.tcp.src_ip;
	printf("%s",inet_ntoa(src1));
	printf("\n\tDestiantion IP: ");
	dst1.s_addr=pkt.tcp.dst_ip;
	printf("%s",inet_ntoa(dst1));
	printf("\nTRANSMISSION CONTROL PROTOCOL");
	printf("\n\tSource Port:%d ",ntohs(pkt.ip.sport));
	printf("\n\tDestination Port: %d   ",ntohs(pkt.ip.dport));
	struct in_addr seq1,ack1;
	printf("\n\tSequence number: ");
	seq1.s_addr = pkt.ip.seq;
	printf("%s ",inet_ntoa(seq1));
	printf("\n\tAcknowledgement number: ");
	ack1.s_addr = pkt.ip.ack;
	printf("%s",inet_ntoa(ack1));
	printf("\n\tHeader Length: %01x ",pkt.ip.hlen);
	printf("\n\tFlags: %01x ",pkt.ip.flags);
	printf("\n\tWindow Size Value: %d ",ntohs(pkt.ip.win_size));
	printf("\n\tChecksum: %d ",ntohs(pkt.ip.check_sum));
	printf("\n\tUrgent Pointer: %d\n ",ntohs(pkt.ip.pointer));
	return 0;
}

