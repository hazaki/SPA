#include "receive.h"

#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};

#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* UDP header */
struct sniff_udp {
	u_short uh_sport;	/* source port */
	u_short uh_dport;	/* destination port */
	u_short uh_ulen; 	/* datagram length */
	u_short uh_sum;		/* datagram checksum */
};

unsigned char *key = "01234567890123456789012345678901";
unsigned char *iv = "01234567890123456";

void callback(u_char *user, const struct pcap_pkthdr *h, const u_char * packet)
{
	//Packet Parsing

	struct connected * connection = (connected *)user;

	const struct sniff_ethernet *ethernet; /* The ethernet header */
	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_udp *udp; /* The TCP header */
	unsigned char *payload; /* Packet payload */

	u_int size_ip;
	u_int size_udp;

        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
	size_udp = sizeof(u_short)*4;
	if (size_udp < 8) {
		printf("   * Invalid UDP header length: %u bytes\n", size_udp);
		return;
	}
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);

	// Payload decryption

	unsigned char hash[32];
	unsigned char plaintext[128];
	int plaintext_len = get_unciphered_payload(payload,key,iv, plaintext, h->len - (SIZE_ETHERNET + size_ip + size_udp), hash);
	plaintext[plaintext_len]='\0';

	//Argument Parsing and TimeStamp Recovering

	int len_port = plaintext_len - 14 -2;

	char num_port[len_port];
	char sec[2];
	char ctime[14];

	memcpy(num_port, plaintext, len_port);
	memcpy(sec, plaintext + len_port, 2);
	memcpy(ctime, plaintext + len_port + 2, 14);
	num_port[len_port]='\0';
	sec[2]='\0';

	//printf("num port :%s",num_port);
	//printf("sec :%s\n",sec);

	int hh, mm, ss, dd, mth, yy;
	sscanf(ctime, "%04d%02d%02d%02d%02d%02d", &yy, &mth, &dd, &hh, &mm, &ss);
	struct tm after_send = {0};
	after_send.tm_mday = dd;
	after_send.tm_mon = mth - 1;
	after_send.tm_year = yy - 1900;
	after_send.tm_hour = hh;
	after_send.tm_min = mm;
	after_send.tm_sec = ss;

	time_t after_tm = mktime(&after_send);

	//printf("%s", asctime(&after_send));

	//Replay detection and Request list update

	int res = add_request(connection, hash, (char *)inet_ntoa(ip->ip_src), atoi(num_port), after_tm + atoi(sec));

	printf("\n Packet \nhash: ");
	print_hash(hash);
	printf("ip : %s\n, port : %s\n, temps:%s\n\n",(char *)inet_ntoa(ip->ip_src),num_port,asctime(&after_send));
	if(res == 0)
		printf("Packet Already received (Replay)\n");
	if(res == -1)
		printf("Invalid Time\n");
	if(res == -2)
		printf("Structure Handling Request is Full\n");

	//print_requests(connection);
	//char command[128];
	//sprintf(command, "iptables -A FORWARD -s %s -p %d", inet_ntoa(ip->ip_src), atoi(plaintext));
	//system(command);
	//system("iptables -L");
	//system("iptables -F");
}

void receive(struct connected * connection)
{
	pcap_t *handle;			  /* Session handle */
	char *dev;			  /* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	  /* Error string */
	struct bpf_program fp;		  /* The compiled filter */
	char filter_exp[] = "port 12346"; /* The filter expression */
	bpf_u_int32 mask;		  /* Our netmask */
	bpf_u_int32 net;		  /* Our IP */
	struct pcap_pkthdr header;	  /* The header that pcap gives us */
	u_char *packet;	      		/* The actual packet */

	/* Define the device, eth0 will be taken by default */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		exit(-1);
	}

	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		exit(-1);
	}

	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(-1);
	}

	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, mask) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(-1);
	}

	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(-1);
	}

	if (pcap_loop(handle,-1,callback,(char *)connection)< 0)
	{
		fprintf(stderr,"pcap_loop : %s\n",pcap_geterr(handle));
		exit(-1);
	}
	//close_connections(connection);
}
