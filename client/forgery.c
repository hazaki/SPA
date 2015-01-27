#include "forgery.h"

void forge(char * interface, char * ip_dest, char * text,int payload_len)
{

    // Vérfication des arguments

    libnet_t *l = NULL;
    char errbuf[LIBNET_ERRBUF_SIZE];
    l = libnet_init(LIBNET_RAW4,interface,errbuf);
    if (l == NULL){
        libnet_destroy(l);
        printf("Erreur descr : %s\n", errbuf);
        exit(-1);
    }

    // Création de l'entête UDP

    libnet_ptag_t udp = 0;
    u_int32_t dst_ip = libnet_name2addr4(l,ip_dest,LIBNET_DONT_RESOLVE);
    if (dst_ip == -1)
    {
        printf("Erreur ip dst\n");
        libnet_destroy(l);
        exit(-1);
    }

    udp = libnet_build_udp(
      12345, /* source port */
      12346, /* destination port */
      LIBNET_UDP_H + payload_len/*add the payload's length*/, /* packet length */
      0, /* checksum */
      (u_int8_t*)text, /* payload */
      payload_len, /* payload size */
      l, /* libnet handle */
      0); /* libnet id */

    if (udp == -1)
    {
      fprintf(stderr, "Can't build UDP header: %s\n", libnet_geterror(l));
      exit(-1);
    }

    // Création de l'entêteP

    libnet_ptag_t ip = 0;
    ip = libnet_autobuild_ipv4(
        LIBNET_IPV4_H + LIBNET_UDP_H,
        IPPROTO_UDP,
        dst_ip,
        l);
    if (ip == -1)
    {
        printf("erreur ip\n");
        libnet_destroy(l);
        exit(-1);
    }
    /*On envoie le paquet */

    libnet_write(l);

    printf("Envoyé\n");

    /*On détruit le descripteur*/
    libnet_destroy(l);
}
