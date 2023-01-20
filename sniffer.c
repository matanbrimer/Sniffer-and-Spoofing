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

FILE *ptr;

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* don't fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
		#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

/* api header is exactly 12 bytes without the data*/
#define SIZE_API 14

/*API header*/
struct sniff_api {
    uint32_t timestamp;
    uint16_t length;
	union {
        uint16_t flags;
        uint16_t reserved:3, c_flag:1, s_flag:1, t_flag:1, status:10;
    };
    uint16_t cache;
    uint16_t padding;
};

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);


/*
 * print data in rows of 16 bytes: offset   hex 
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	fprintf(ptr,"%05d   ", offset);
	printf("%05d   ", offset);
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		fprintf(ptr,"%02x ", *ch);
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			fprintf(ptr," ");
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		fprintf(ptr," ");
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			fprintf(ptr,"   ");
			printf("   ");
		}
	}
	fprintf(ptr,"   ");
	fprintf(ptr,"\n");
	printf("   ");
	printf("\n");

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

	static int count = 1;                   /* packet counter */

	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	struct sniff_api *api;                  /* The API header*/
	const char *payload;                     /*The messege*/

	int size_ip;
	int size_tcp;
	int size_api;
	int size_payload;

	/* create a txt file and write all the packets data inside it*/
	ptr = fopen("316332311.txt", "a");

	fprintf(ptr,"\nPacket number %d:\n\n", count);
	count++;
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);

	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	
	/* determine protocol */
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			printf("   Protocol: TCP\n");
			break;
		case IPPROTO_UDP:
			printf("   Protocol: UDP\n");
			return;
		case IPPROTO_ICMP:
			printf("   Protocol: ICMP\n");
			return;
		case IPPROTO_IP:
			printf("   Protocol: IP\n");
			return;
		default:
			printf("   Protocol: unknown\n");
			return;
	}

	/*
	 *  OK, this packet is TCP.
	 */

	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}

	
	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

	
	
	// ==============================
	//		     PRINTS
	// ==============================

	fprintf(ptr,"------------- IP header -------------\n");

	/* print source IP addresses */
	fprintf(ptr,"source_ip: <%s>\n", inet_ntoa(ip->ip_src));

    /* print destination IP addresses */
	fprintf(ptr,"dest_ip: <%s>\n\n", inet_ntoa(ip->ip_dst));

	fprintf(ptr,"------------- TCP header -------------\n");

    /* print source Port */
    fprintf(ptr,"source_port: <%d>\n", ntohs(tcp->th_sport));

    /* print destination Port */
	fprintf(ptr,"dest_port: <%d>\n\n", ntohs(tcp->th_dport));


	if (size_payload > 0) {

		api = (struct sniff_api*)(packet + SIZE_ETHERNET + size_ip + size_tcp);
		size_api = SIZE_API;
	
		/* define/compute payload offset */
		payload = (packet + SIZE_ETHERNET + size_ip + size_tcp + SIZE_API);
		size_payload = ntohs(api->length) - SIZE_API;

		fprintf(ptr,"------------- API header -------------\n");

    	/* print timestamp */
    	fprintf(ptr,"timestamp: <%d>\n", ntohl(api->timestamp));

    	/* print total length */
		fprintf(ptr,"total_length: <%d>\n", ntohs(api->length));

		/* change flags field in api header to host byte order*/
		api->flags = ntohs(api->flags);

    	/* print cache flag */
		fprintf(ptr,"cache_flag: <%d>\n", ((api->flags) >> 12) & 1);

    	/* print steps flag */
		fprintf(ptr,"steps_flag: <%d>\n", ((api->flags) >> 11) & 1);

    	/* print type flag */
		fprintf(ptr,"type_flag: <%d>\n", ((api->flags) >> 10) & 1);

    	/* print status code */
		fprintf(ptr,"status_code: <%d>\n", api->status);

   	 	/* print cache control */
		fprintf(ptr,"cache_control: <%d>\n", api->cache);

		/* Print payload data */
		fprintf(ptr,"------------- Data -------------\n");
		print_payload(payload, size_payload);
	}

	/* close the file */
	fclose(ptr);
	return;
}

int main() {

	char *dev = "enp0s3";			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];	/* error buffer */
	pcap_t *handle;					/* packet capture handle */
	char filter_exp[] = "tcp";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;				/* subnet mask */
	bpf_u_int32 net;				/* ip */

	
	
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

	/* create a txt file and write all the packets data inside it*/
	ptr = fopen("316332311.txt", "w");

	/* now we can set our callback function */
	pcap_loop(handle, -1, got_packet, NULL);

	/* close the file */
	fclose(ptr);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

return 0;
}
