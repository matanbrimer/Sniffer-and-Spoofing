#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <netinet/tcp.h>


/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518
/* IP Header */
struct ipheader
{
    unsigned char       iph_ihl : 4,    // IP header length
                        iph_ver : 4;    // IP version
    unsigned char       iph_tos;        // Type of service
    unsigned short int  iph_len;        // IP Packet length (data + header)
    unsigned short int  iph_ident;      // Identification
    unsigned short int  iph_flag : 3,   // Fragmentation flags        
                        iph_offset : 13;// Flags offset
    unsigned char       iph_ttl;        // Time to Live 
    unsigned char       iph_protocol;   // Protocol type
    unsigned short int  iph_chksum;     // IP datagram checksum
    struct in_addr      iph_sourceip;   // Source IP address
    struct in_addr      iph_destip;     // Destination IP address
};
/* ICMP Header  */
struct icmpheader
{
    unsigned char icmp_type;        // ICMP message type
    unsigned char icmp_code;        // Error code
    unsigned short int icmp_chksum; // Checksum for ICMP Header and data
    unsigned short int icmp_id;     // Used for identifying request
    unsigned short int icmp_seq;    // Sequence number
    unsigned short int time;
};

void send_raw_ip_packet(struct ipheader *ip);
void icmp_packet(struct ipheader *ip_2,struct icmpheader *icmp_2);
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
unsigned short in_cksum(unsigned short *buf, int length)
{
    unsigned short *w = buf;
    int nleft = length;
    int sum = 0;
    unsigned short temp = 0;

    /*
     * The algorithm uses a 32 bit accumulator (sum), adds
     * sequential 16 bit words to it, and at the end, folds back all
     * the carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    /* treat the odd byte at the end, if any */
    if (nleft == 1)
    {
        *(u_char *)(&temp) = *(u_char *)w;
        sum += temp;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    return (unsigned short)(~sum);
}


/*
 * dissect/print packet
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    
	struct ipheader *ip = (struct ipheader *) (packet + sizeof(struct ether_header));	
	struct icmpheader *icmp = (struct icmpheader *) (packet + sizeof(struct ether_header) + sizeof(struct ipheader));

    char* saddr = inet_ntoa(ip_2->iph_sourceip);

    printf("source ip: %s\n," ,saddr);
    char *daddr = inet_ntoa(ip_2->iph_destip);

    printf("destintion ip: %s \n",daddr);


    	if(icmp->icmp_type == 8){
           icmp_packet(ip,icmp);
        }
    
		
}
/****************************************************************** 
  Spoof an ICMP echo request using an arbitrary source IP Address
*******************************************************************/

void icmp_packet(struct ipheader *ip_2,struct icmpheader *icmp_2)
{
     
     char buffer[1500];
    memset(buffer, 0, 1500);

    // Step 1: Fill in the ICMP header.

    struct icmpheader *icmp = (struct icmpheader *)(buffer + sizeof(struct ipheader));
    icmp->icmp_type = 0; // ICMP Type: 8 is request, 0 is reply.
    icmp->icmp_seq = icmp_2->icmp_seq;
    // Calculate the checksum for integrity
    icmp->icmp_chksum = 0;
    icmp->icmp_id = icmp_2->icmp_id;
    icmp->icmp_code = icmp_2->icmp_code;
  
    icmp->icmp_chksum = in_cksum((unsigned short *)icmp,sizeof(struct icmpheader));
    
    // Step 2: Fill in the IP header.

    struct ipheader *ip = (struct ipheader *)buffer;
    struct in_addr su ;
    
    su.s_addr = ip_2->iph_sourceip.s_addr;
    ip->iph_ver = ip_2->iph_ver;
    ip->iph_ihl = ip_2->iph_ihl;
    ip->iph_ttl = ip_2->iph_ttl;
    ip->iph_sourceip.s_addr = ip_2->iph_destip.s_addr;
    ip->iph_destip.s_addr = su.s_addr;
    ip->iph_protocol = IPPROTO_ICMP;
     ip->iph_len =  (htons(sizeof(struct ipheader) +sizeof(struct icmpheader)));
   // ip->iph_len = ip_2->iph_len;
    ip->iph_chksum =in_cksum((unsigned short *)ip,sizeof(struct ipheader));
    // Step 3: Finally, send the spoofed packet

    send_raw_ip_packet(ip);
}
void send_raw_ip_packet(struct ipheader *ip)
{
    struct sockaddr_in dest_info;
    int enable = 1;
   
    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Step 2: Set socket option.
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)); // IP_HDRINCL to tell the kernel that headers are included in the packet

    // Step 3: Provide needed information about destination.
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;
   
    // Step 4: Send the packet out.
    sendto(sock, ip, ntohs(ip->iph_len), 0,
           (struct sockaddr *)&dest_info, sizeof(dest_info));
    close(sock);
}

/******************************************************************
  Spoof an ICMP echo request using an arbitrary source IP Address
*******************************************************************/


int main(){
   pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "icmp";
	bpf_u_int32 net;
    char *dev = "enp0s3";//"br-0c101745eb14";//	
	bpf_u_int32 mask;

	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Filter expression: %s\n", filter_exp);

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}


	printf("Capturing ICMP Packets.....\n");
	// Step 3: Capture packets
	pcap_loop(handle, -1, got_packet, NULL);

	pcap_close(handle); //Close the handle
    pcap_freecode(&fp);

    return 0;
}