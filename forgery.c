#include <stdio.h>
#include <libnet.h>
#include <unistd.h>

int main()
{
  
    libnet_t *l = NULL;
    char errbuf[LIBNET_ERRBUF_SIZE];
    l = libnet_init(LIBNET_RAW4,"eth0",errbuf);
    if (l == NULL){
        libnet_destroy(l);
        printf("Erreur descr : %s\n", errbuf);
        return -1;}
        
    // Création de l'entête UDP
    
    libnet_ptag_t udp = 0;
    u_int32_t dst_ip = libnet_name2addr4(l,"192.168.128.1",LIBNET_DONT_RESOLVE);
    if (dst_ip == -1)
    {
        printf("Erreur ip dst\n");
        libnet_destroy(l);
        return -1;
    }
    
    udp = libnet_build_udp(
      54, /* source port */
      53, /* destination port */
      LIBNET_UDP_H + LIBNET_UDP_DNSV4_H /*add the payload's length*/, /* packet length */
      0, /* checksum */
      NULL, /* payload */
      0, /* payload size */
      l, /* libnet handle */
      0); /* libnet id */

    if (udp == -1)
    {
      fprintf(stderr, "Can't build UDP header: %s\n", libnet_geterror(l));
      return -1;
    }
    
    // Création de l'entête IP    
    
    libnet_ptag_t ip = 0;
    ip = libnet_autobuild_ipv4(
        LIBNET_IPV4_H + LIBNET_TCP_H,
        IPPROTO_TCP,
        dst_ip,
        l);
    if (ip == -1)
    {
        printf("erreur ip\n");
        libnet_destroy(l);
        return -1;
    }
    /*On envoie le paquet */
    while(1){
    libnet_write(l);
    }
    printf("Envoyé\n");
    /*On détruit le descripteur*/
    libnet_destroy(l);
 
    return 0;
 
}
