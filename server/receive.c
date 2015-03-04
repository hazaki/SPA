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

int MAX_REQUEST = 1024;
int LEN_SEC = 2;
int LEN_PROTO = 3;
int LEN_TIME = 14;

#define HMAC_LEN 40

char seed[HMAC_LEN]="0123456789012345678901234567890123456789";

struct connected * connection;

char * ip_server;

void callback(u_char *user, const struct pcap_pkthdr *h, const u_char * packet)
{
	//Packet Parsing

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

	char * cip_src = (char *)inet_ntoa(ip->ip_src);

	// Payload decryption

	//OTP Recovering

	//seed and counter recovering
	xmlDocPtr doc;
        doc = xmlParseFile("connections.xml");
        if (doc == NULL) {
                fprintf(stderr, "Invalid XML file\n");
                return ;
        }

        //recover counter
        int counter;
        counter = atoi(getCount(doc,cip_src));

        //recover seed
        char * seed;
        char password[HMAC_LEN];
        seed = getSeed(doc,cip_src);

	//recover seed - save no information as long as you're not sur about the client's identity
	hmac(seed, counter, HMAC_LEN, password);

	unsigned char hash[32];
	unsigned char plaintext[128];
	int plaintext_len = get_unciphered_payload(payload, password, plaintext, h->len - (SIZE_ETHERNET + size_ip + size_udp), hash);
	plaintext[plaintext_len]='\0';
	printf("plaintext : %s\n", plaintext);
	//Payload Parsing and TimeStamp Recovering

	char header_ip_src[15];
	sprintf(header_ip_src,"%s",(char *)inet_ntoa(ip->ip_src));
	int len_ip = strlen(header_ip_src);

	char payload_ip_src[15];

	memcpy(payload_ip_src, plaintext, len_ip);

	if(strncmp(header_ip_src,payload_ip_src,len_ip)!=0)
		return ;

	int len_port = plaintext_len - len_ip - LEN_PROTO - LEN_SEC - LEN_TIME;
	char num_port[len_port];
	char sec[LEN_SEC];
	char ctime[LEN_TIME];
	char protocol[LEN_PROTO];


	memcpy(num_port, plaintext + len_ip, len_port);
	memcpy(protocol, plaintext + len_ip + len_port, LEN_PROTO);
	memcpy(sec, plaintext + len_ip + len_port + LEN_PROTO, LEN_SEC);
	memcpy(ctime, plaintext +len_ip + len_port + LEN_PROTO + LEN_SEC, LEN_TIME);
	num_port[len_port]='\0';
	sec[LEN_SEC]='\0';
	protocol[3]='\0';

	//printf("port : %s\nprotocole : %s\nsec :%s\ntime : %s\n",num_port,protocol,sec,ctime);

	time_t now = time(NULL);

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

	//Replay detection

	int res = add_request(connection, hash, (char *)inet_ntoa(ip->ip_src), atoi(num_port), protocol, after_tm + atoi(sec));

	if(res == 0)
	{
		printf("Packet Already received (Replay)\n");
		return;
	}
	if(res == -1)
	{
		printf("Invalid Time\n");
		return;
	}
	if(res == -2)
	{
		printf("Structure Handling Request is Full\n");
		return;
	}

	//OTP

	//increment counter and save information
	counter++;

	char ccounter[20];
        sprintf(ccounter, "%d", counter);
        printf("counter %s\n",ccounter);

        setCountValue(doc, cip_src, ccounter);

        //writting in XML file
        FILE* file = NULL;
        file = fopen("connections.xml", "w");
        if(file== NULL){
                fprintf(stderr, "Error while opening file\n");
        }
        xmlDocDump(file, doc);

        fclose(file);

        // free memory
        xmlFreeDoc(doc);

	//Firewall Rule
	print_requests(connection);
	char command[128];
	sprintf(command, "iptables -A FORWARD -s %s -d %s -p %s --dport %d -j ACCEPT", inet_ntoa(ip->ip_src), ip_server, protocol, atoi(num_port));
	system(command);

        sprintf(command, "iptables -A FORWARD -d %s -s %s -p %s -m state --state ESTABLISHED -j ACCEPT", inet_ntoa(ip->ip_src), ip_server, protocol);
        system(command);

	system("iptables -L -n");

	//ALARM LAUNCHING
	alarm(connection->first->end_time - now);
}

void sighandler(int signum)
{
	printf("Caught signal for end_time :");
	printf("%s", asctime((localtime(&connection->first->end_time))));

	char command[128];
	sprintf(command, "iptables -D FORWARD -s %s -d %s -p %s --dport %d -j ACCEPT", connection->first->ip, ip_server, connection->first->protocol, connection->first->port);
        system(command);

        sprintf(command, "iptables -D FORWARD -d %s -s %s -p %s -m state --state ESTABLISHED -j ACCEPT", connection->first->ip, ip_server, connection->first->protocol);
        system(command);

	del_request(connection);

	system("iptables -L -n");

	if(connection->first != NULL)
	{
   		time_t now = time(NULL);
		alarm(connection->first->end_time - now);
	}
}



void receive(char * ip)
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

	connection = init_connected(MAX_REQUEST);

	ip_server = ip;

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

	signal(SIGALRM, sighandler);

	if (pcap_loop(handle,-1,callback,packet)< 0)
	{
		fprintf(stderr,"pcap_loop : %s\n",pcap_geterr(handle));
		exit(-1);
	}
	close_connections(connection);
}
