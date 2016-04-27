#include <pcap/pcap.h>
#include <libnet.h>
#include <netinet/in.h>


struct libnet_arp_hdr
{
    uint16_t ar_hrd;         /* format of hardware address */
#define ARPHRD_NETROM   0   /* from KA9Q: NET/ROM pseudo */
#define ARPHRD_ETHER    1   /* Ethernet 10Mbps */
#define ARPHRD_EETHER   2   /* Experimental Ethernet */
#define ARPHRD_AX25     3   /* AX.25 Level 2 */
#define ARPHRD_PRONET   4   /* PROnet token ring */
#define ARPHRD_CHAOS    5   /* Chaosnet */
#define ARPHRD_IEEE802  6   /* IEEE 802.2 Ethernet/TR/TB */
#define ARPHRD_ARCNET   7   /* ARCnet */
#define ARPHRD_APPLETLK 8   /* APPLEtalk */
#define ARPHRD_LANSTAR  9   /* Lanstar */
#define ARPHRD_DLCI     15  /* Frame Relay DLCI */
#define ARPHRD_ATM      19  /* ATM */
#define ARPHRD_METRICOM 23  /* Metricom STRIP (new IANA id) */
#define ARPHRD_IPSEC    31  /* IPsec tunnel */
    uint16_t ar_pro;         /* format of protocol address */
    uint8_t  ar_hln;         /* length of hardware address */
    uint8_t  ar_pln;         /* length of protocol addres */
    uint16_t ar_op;          /* operation type */
#define ARPOP_REQUEST    1  /* req to resolve address */
#define ARPOP_REPLY      2  /* resp to previous request */
#define ARPOP_REVREQUEST 3  /* req protocol address given hardware */
#define ARPOP_REVREPLY   4  /* resp giving protocol address */
#define ARPOP_INVREQUEST 8  /* req to identify peer */
#define ARPOP_INVREPLY   9  /* resp identifying peer */
    /* address information allocated dynamically */

    uint16_t attack_HA[ETHER_ADDR_LEN];         /* attack of hardware address */
    uint16_t victim_HA[ETHER_ADDR_LEN];         /* victim of hardware address */
    struct in_addr ip_src, ip_dst; /* source and dest address */

};



int main()

{
    char *dev, errbuf[PCAP_ERRBUF_SIZE]; /* The device to sniff on, Error string */

    /* Define the device */
    dev = pcap_lookupdev(errbuf); //find the dev
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    printf("Device: %s\n", dev);

    pcap_t *handle; /* Session handle */

    /* Open the session in promiscuous mode */
      handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); // dev session open
      if (handle == NULL) {
          fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
          return(2);
      }

      char send_buf[sizeof(libnet_ethernet_hdr) + sizeof(libnet_arp_hdr)] =  {0,}; // send_buf[0], send_buf[1], send_buf[2]
      libnet_ethernet_hdr* eth_hdr = (libnet_ethernet_hdr*)send_buf;
      // eth_hdr setting place
      // victim MAC address setting
      // if i want to arp snooping to everyone of netwrok you can write FF-FF-FF-FF-FF-FF
      send_buf[0] = 0xD0;
      send_buf[1] = 0x50;
      send_buf[2] = 0x99;
      send_buf[3] = 0xA4;
      send_buf[4] = 0x04;
      send_buf[5] = 0x4D;

      // attcker Mac address setting
      send_buf[6] = 0x00;
      send_buf[7] = 0x0c;
      send_buf[8] = 0x29;
      send_buf[9] = 0xe1;
      send_buf[10] = 0xaa;
      send_buf[11] = 0x9a;

      //arp type setting
      eth_hdr -> ether_type = ETHERTYPE_ARP;

      printf("                  ** eth0 **\n");
      printf("      Attcker MAC    ->    Victim MAC \n");
      printf("   %02X:%02X:%02X:%02X:%02X:%02X -> %02X:%02X:%02X:%02X:%02X:%02X\n\n\n",
                  eth_hdr->ether_shost[0],
                  eth_hdr->ether_shost[1],
                  eth_hdr->ether_shost[2],
                  eth_hdr->ether_shost[3],
                  eth_hdr->ether_shost[4],
                  eth_hdr->ether_shost[5],
                  eth_hdr->ether_dhost[0],
                  eth_hdr->ether_dhost[1],
                  eth_hdr->ether_dhost[2],
                  eth_hdr->ether_dhost[3],
                  eth_hdr->ether_dhost[4],
                  eth_hdr->ether_dhost[5]);


      if(eth_hdr -> ether_type == ETHERTYPE_ARP)
      {
          libnet_arp_hdr* arp_hdr = (libnet_arp_hdr*)(send_buf + sizeof(libnet_ethernet_hdr));

          arp_hdr -> ar_hrd = ARPHRD_ETHER;
          arp_hdr -> ar_pro = ETHERTYPE_IP;
          arp_hdr -> ar_hln = 0x06;
          arp_hdr -> ar_pln = 0x04;
          if(arp_hdr -> ar_op == ARPOP_REQUEST || arp_hdr -> ar_op == ARPOP_REPLY)
          {
          printf("   %02X:%02X:%02X:%02X:%02X:%02X -> %02X:%02X:%02X:%02X:%02X:%02X\n\n\n",
                      arp_hdr->attack_HA[0] = 0x08,
                      arp_hdr->attack_HA[1] = 0x08,
                      arp_hdr->attack_HA[2],
                      arp_hdr->attack_HA[3],
                      arp_hdr->attack_HA[4],
                      arp_hdr->attack_HA[5],
                      arp_hdr->victim_HA[0],
                      arp_hdr->victim_HA[1],
                      arp_hdr->victim_HA[2],
                      arp_hdr->victim_HA[3],
                      arp_hdr->victim_HA[4],
                      arp_hdr->victim_HA[5]);
              }
      }





      // ar_hdr setting

      //vmware: ip = 10.100.111.105 // MAC = 00:0c:29:e1:aa:9a
      //window: ip = 10.100.111. 98 // MAC = D0-50-99-A4-04-4D


      pcap_close(handle);

   return(0);

}


/*===========  get Src Mac, Dst Mac(eth0) ==========*/
/*
printf("                  ** eth0 **\n");
printf("      Source MAC     ->  Destination MAC\n");
printf("   %02X:%02X:%02X:%02X:%02X:%02X -> %02X:%02X:%02X:%02X:%02X:%02X\n\n\n",
            ehP->ether_shost[0],
            ehP->ether_shost[1],
            ehP->ether_shost[2],
            ehP->ether_shost[3],
            ehP->ether_shost[4],
            ehP->ether_shost[5],
            ehP->ether_dhost[0],
            ehP->ether_dhost[1],
            ehP->ether_dhost[2],
            ehP->ether_dhost[3],
            ehP->ether_dhost[4],
            ehP->ether_dhost[5]);*/

/*===========  get Src ip, Dst ip(IP) ==========*/


/*if(ntohs(ehP->ether_type) == ETHERTYPE_IP)
  {
      struct libnet_ipv4_hdr* ihP;
      ihP = (struct libnet_ipv4_hdr*)(p + sizeof(*ehP)); //ehp == 14

      printf("               ** EHTERTYPE_IP **\n");
      printf("      Source IP     ->    Destination IP   \n");
      printf("     %s     ", inet_ntoa(ihP->ip_src));
      printf("-> %15s    \n\n\n", inet_ntoa(ihP->ip_dst));

      /*===========  get Src, Dst port(TCP) ==========*/

  /*    if(ihP->ip_p == IPPROTO_TCP){
      struct libnet_tcp_hdr *tcph;
      tcph = (struct libnet_tcp_hdr *)(ihP + 1); //find next pointer
      printf("               ** TCP Information **\n");
      printf("     Src Port : %d\n" , ntohs(tcph->th_sport));
      printf("     Dst Port : %d\n\n\n" , ntohs(tcph->th_dport));
      /*printf("%d\n", ihP->ip_hl * 4);*/
    //  }

      /*===========  get Src, Dst port(UDP) ==========*/

      /*else if(ihP->ip_p == IPPROTO_UDP)
      {
          struct libnet_udp_hdr *udph;
          udph = (struct libnet_udp_hdr *)(ihP + 1); //find next pointer
          printf("               ** UDP Information **\n");
          printf("     Src Port : %d\n" , ntohs(udph->uh_sport));
          printf("     Dst Port : %d\n" , ntohs(udph->uh_sport));
      }
  }*/

