#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>

void callback(u_char *user,const struct pcap_pkthdr *h, const u_char *buff)
{
	printf("J'ai reçu quelque chose !\n");
}

int main()
{
	char errbuf[PCAP_ERRBUF_SIZE];
	char *dev=NULL,*buff=NULL;
	pcap_t *pdes;
	bpf_u_int32 net,mask;
	struct bpf_program bp;
	char filter[350];
	int optch;

    if((dev=pcap_lookupdev(errbuf)) == NULL)
    {
		fprintf(stderr,"unable de detect device : %s\n",errbuf);
		exit(-1);
    }
	printf("using %s as device for sniffing\n",dev);

	if(pcap_lookupnet(dev,&net,&mask,errbuf)==-1)
	{
		fprintf(stderr,"unable to lookup net and mask : %s\n",errbuf);
		exit(-1);
	}

    if((pdes=pcap_open_live(dev,1514,IFF_PROMISC,1000,errbuf)) == NULL)
    {
	    fprintf(stderr,"unable to open descriptor : %s\n",errbuf);
	    exit(-1);
	}
	
	if(pcap_compile(pdes,&bp,filter,0x100,mask)<0) 
	{
		fprintf(stderr,"compile error : %s\n",pcap_geterr(pdes));
		exit(-1);
	}

	if(pcap_setfilter(pdes,&bp)<0) 
	{
		fprintf(stderr,"unable to set filter : %s\n",pcap_geterr(pdes));
		exit(-1);
	}

	if(pcap_loop(pdes,-1,callback,buff)<0) 
	{
		fprintf(stderr,"pcap_loop : %s\n",pcap_geterr(pdes));
		exit(-1);
	}
	
	return 0;
}
