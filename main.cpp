#include <pcap/pcap.h>
#include <libnet.h>
#include <netinet/in.h>


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

      while(1){
                          struct pcap_pkthdr *h;
                          const u_char * p;
                          int res = pcap_next_ex(handle, &h, &p);
                          if(res == 0){printf("No packet is sniffed..!!");break;}
                          if(res == -1) break;


                          struct libnet_ethernet_hdr *ehP = (struct libnet_ethernet_hdr *)p;

                          /*===========  get Src Mac, Dst Mac(eth0) ==========*/

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
                                      ehP->ether_dhost[5]);

                         /*===========  get Src ip, Dst ip(IP) ==========*/


                          if(ntohs(ehP->ether_type) == ETHERTYPE_IP)
                            {
                                struct libnet_ipv4_hdr* ihP;
                                ihP = (struct libnet_ipv4_hdr*)(p + sizeof(*ehP)); //ehp == 14

                                printf("               ** EHTERTYPE_IP **\n");
                                printf("      Source IP     ->    Destination IP   \n");
                                printf("     %s     ", inet_ntoa(ihP->ip_src));
                                printf("-> %15s    \n\n\n", inet_ntoa(ihP->ip_dst));

                                /*===========  get Src, Dst port(TCP) ==========*/

                                if(ihP->ip_p == IPPROTO_TCP){
                                struct libnet_tcp_hdr *tcph;
                                tcph = (struct libnet_tcp_hdr *)(ihP + 1); //34 + TCP/UDP header palce
                                printf("%d -> %d", ihP->ip_hl*4, sizeof(*ihP));

                                printf("               ** TCP Information **\n");
                                printf("     Src Port : %d\n" , ntohs(tcph->th_sport));
                                printf("     Dst Port : %d\n\n\n" , ntohs(tcph->th_dport));
                                /*printf("%d\n", ihP->ip_hl * 4);*/
                                }

                                /*===========  get Src, Dst port(UDP) ==========*/

                                else if(ihP->ip_p == IPPROTO_UDP)
                                {
                                    struct libnet_udp_hdr *udph;
                                    udph = (struct libnet_udp_hdr *)(ihP + 1); //34 + TCP/UDP header palce
                                    printf("               ** UDP Information **\n");
                                    printf("     Src Port : %d\n" , ntohs(udph->uh_sport));
                                    printf("Dst Port : %d\n" , ntohs(udph->uh_sport));
                                }
                            }

               }
      pcap_close(handle);

   return(0);

}


