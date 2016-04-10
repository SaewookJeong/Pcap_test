#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>


int eth_hdr = 0;
int ip_hdr = eth_hdr + 12;
int tcp_hdr = ip_hdr + 20;
int udp_hdr = ip_hdr + 20;


void get_pcap(u_char *args, const struct pcap_pkthdr *header, const u_char *p)
{


    int des, src, sum;

    /*============ Ethernet ==========*/
    printf("    <Ethernet> - src mac: ");
    for(src = eth_hdr + 6; src < eth_hdr + 12 ; src++)
    {
        if(src == 11)printf("%02X", p[src]);
        else printf("%02X:", p[src]);
    }
    printf("\n");

    printf("    <Ethernet> - dst mac: ");
    for(des = eth_hdr; des < eth_hdr + 6; des++)
    {
        if(des == 5)printf("%02X", p[des]);
        else printf("%02X:", p[des]);
    }
    printf("\n\n\n");

    /*========== IP ===========*/
    if(p[ip_hdr] == 8 && p[ip_hdr+1] == 0) //p[14] = Header Length
    printf("    <IP> - src ip: ");

    for(src = ip_hdr + 14; src < ip_hdr + 18; src++) //src ip: 26~29
    {
        if(src == 29)printf("%d", p[src]);
        else printf("%d.", p[src]);
    }
    printf("\n");

    printf("    <IP> - dst ip: ");
    for(des = ip_hdr + 18; des < ip_hdr + 22; des++) // dst ip: 30 ~ 33
    {
        if(des == 33)printf("%d", p[des]);
        else printf("%d.", p[des]);
    }
    printf("\n\n\n");

    /*========== TCP ===========*/

    if(p[23] == 6) // p[23] == 6 TCP port
        {
            printf("    <TCP> - Source Port: ");

            printf("%d, ",p[34]);
            printf("%d\n",p[35]);

        }
}



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

      pcap_loop(handle, -1, get_pcap, NULL);

      pcap_close(handle);

   return(0);

}


