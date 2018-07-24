#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}
typedef struct TCP_Header
{
	u_short src_port;
	u_short des_port;
	u_int seq_num;
	u_int ack_num;
	u_char reserved:4;
	u_char H_length:4;
	u_char flag;
	u_short window;
	u_short checksum;
	u_short urgent;
}TCP_h;
typedef struct IP_Header
{
	u_char H_length : 4;
	u_char version : 4;
	u_char service;
	u_short P_length;
	u_short ident;
	u_short flag;
	u_char TTL;
	u_char transport;
	u_short checksum;
	u_char src_addr[4];
	u_char des_addr[4];
}IP_h;

typedef struct Ethernet
{
	u_char des_mac[6];
	u_char src_mac[6];
	short type;
}Ethernet;

int main(int argc, char* argv[]) {
  
  Ethernet *eth;
  IP_h * iph;
  TCP_h * tcph;

  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    //printf("%u bytes captured\n", header->caplen);
    eth = (struct Ethernet*)packet;
    printf("=====Ethernet Header======\n");
    printf("des MAC : %02x-%02x-%02x-%02x-%02x-%02x\n",eth->des_mac[0],eth->des_mac[1],eth->des_mac[2],eth->des_mac[3],eth->des_mac[4],eth->des_mac[5]);
    printf("src MAC : %02x-%02x-%02x-%02x-%02x-%02x\n",eth->src_mac[0],eth->src_mac[1],eth->src_mac[2],eth->src_mac[3],eth->src_mac[4],eth->src_mac[5]);
   
    if(eth->type == 0x0008)
    {
      iph = (IP_h*)(packet+14);
	printf("---------IP Header-------\n");
	printf("H_length : %d\n",iph->H_length*4);
	printf("src addr : %d.%d.%d.%d\n",iph->src_addr[0],iph->src_addr[1],iph->src_addr[2],iph->src_addr[3]);
	printf("des_addr : %d.%d.%d.%d\n",iph->des_addr[0],iph->des_addr[1],iph->des_addr[2],iph->des_addr[3]);
	printf("Protocol : %d\n",iph->transport);
	if(iph->transport == 0x06)
	{
		tcph = (TCP_h*)(packet+14+iph->H_length*4);
		printf("---------TCP Header-------\n");
		printf("src_port : %d\n",htons(tcph->src_port));
		printf("des_port : %d\n",htons(tcph->des_port));
		printf("length : %x\n",tcph->H_length);
		printf("checksum : %x\n", htons(tcph->checksum));
	}
	printf("Data : ");
	for(int i=14+iph->H_length*4+tcph->H_length*4; i<=14+iph->H_length*4+tcph->H_length*4+15 ;i++)
	{
		printf("%02x ", packet[i]);
	}
	printf("\n");
	
    }
    printf("==========================\n");
    printf("\n"); 
  }

  pcap_close(handle);
  return 0;
}
