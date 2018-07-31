#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#define ETHERTYPE_IP 0x800
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_IPV6 0x86dd

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
    
    eth = (struct Ethernet*)packet;
    printf("====================================\n");
    printf("-----------Ethernet Header----------\n");
    printf("src MAC : %02x-%02x-%02x-%02x-%02x-%02x\n",eth->src_mac[0],eth->src_mac[1],eth->src_mac[2],eth->src_mac[3],eth->src_mac[4],eth->src_mac[5]);
    printf("des MAC : %02x-%02x-%02x-%02x-%02x-%02x\n",eth->des_mac[0],eth->des_mac[1],eth->des_mac[2],eth->des_mac[3],eth->des_mac[4],eth->des_mac[5]);
    printf("type : %04x\n",ntohs(eth->type));   
    if(ntohs(eth->type) == ETHERTYPE_IP)
    {
      iph = (IP_h*)(packet+14);
      	printf("--------------IP Header-------------\n");
	printf("version : %d\n",iph->version);
	printf("Header length : %d\n",iph->H_length*4);
	printf("service : 0x%02x\n",ntohs(iph->service));
	printf("Total Length : %d\n",ntohs(iph->P_length));
	printf("Identfication : 0x%04x\n", ntohs(iph->ident));
	printf("flag : 0x%04x\n",ntohs(iph->flag));
	printf("Time To Live : %d\n",iph->TTL);
	printf("Protocol : %d\n",iph->transport);
	printf("Checksum : 0x%04x\n",ntohs(iph->checksum));
	printf("src addr : %d.%d.%d.%d\n",iph->src_addr[0],iph->src_addr[1],iph->src_addr[2],iph->src_addr[3]);
	printf("des_addr : %d.%d.%d.%d\n",iph->des_addr[0],iph->des_addr[1],iph->des_addr[2],iph->des_addr[3]);
	
	if(iph->transport == 0x06)
	{
		tcph = (TCP_h*)(packet+14+iph->H_length*4);
		printf("---------TCP Header-------\n");
		printf("src_port : %d\n",htons(tcph->src_port));
		printf("des_port : %d\n",htons(tcph->des_port));
		printf("sequence number : 0x%04x\n",htonl(tcph->seq_num));
		printf("acknowledgement number : 0x%04x\n", htonl(tcph->ack_num));
		printf("header length : %d\n",tcph->H_length*4);
		printf("flags : 0x%02x%02x\n",tcph->reserved,tcph->flag);
		printf("window : 0x%04x\n",htons(tcph->window));
		printf("checksum : 0x%04x\n", htons(tcph->checksum));
		printf("Urgent Pointer : 0x%04x\n", htons(tcph->urgent));
			
		// ALL TCP Data
		if(ntohs(iph->P_length)-iph->H_length*4-tcph->H_length*4 < 16 )
		{
			for(int i=14+iph->H_length*4+tcph->H_length*4; i<14+ntohs(iph->P_length) ;i++)
			{			
				if((i-14-iph->H_length*4-tcph->H_length*4) %16 == 0)
				{
					printf("\n");		
				}	
				printf("%02x ", packet[i]);
			}	
			printf("\n");
		}else
		{
			int loc = 14+iph->H_length*4+ tcph->H_length*4;

			for(int i=0;i<16;i++)
				printf("%02x ", packet[loc+i]);
			printf("\n");
		}
	}
    }
    printf("====================================\n");
    printf("\n"); 
  }

  pcap_close(handle);
  return 0;

}
