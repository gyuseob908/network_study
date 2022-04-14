#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>
#include "pcap_header.h"

void print_packet(const u_char *packet, struct pcap_pkthdr *header){
    struct libnet_ethernet_hdr *ether=(struct libnet_ethernet_hdr *)packet;
    struct libnet_ipv4_hdr *ipv4=(struct libnet_ipv4_hdr *)(packet+sizeof(struct libnet_ethernet_hdr));
    struct libnet_tcp_hdr *tcp=(struct libnet_tcp_hdr *)((void *)ipv4 + ipv4->ip_hl * 4);

    if(ntohs(ether->ether_type)==ETH_TYPE_IPV4){
        if(ipv4->ip_p==IP_PROTOCOL_TCP){
            printf("****Ethernet Header****\n");
            printf("src mac : ");
            for(int i=0;i<ETHER_ADDR_LEN;i++)
                printf("%02X", ether->ether_shost[i]);

            printf("\n");

            printf("dst mac : ");
            for(int i=0;i<ETHER_ADDR_LEN;i++)
                printf("%02X", ether->ether_dhost[i]);

            printf("\n");

            printf("****IP Header****\n");
            printf("src ip : ");
            for(int i=0;i<IPV4_ADDR_LEN;i++)
                printf("%d", ipv4->ip_src[i]);

            printf("\n");

            printf("dst ip : ");
            for(int i=0;i<IPV4_ADDR_LEN;i++)
                printf("%d", ipv4->ip_dst[i]);

            printf("\n");

            printf("****TCP Header****\n");
            printf("src port : %d\n", tcp->th_sport);
            printf("dst port : %d\n", tcp->th_dport);


            uint32_t pay=sizeof(struct libnet_ethernet_hdr) + ipv4->ip_hl * 4 + tcp->th_off * 4;
            printf("Payload : ");
            for(int i=0;pay<header->caplen;pay++){
                if(i==8)
                    break;
                printf("%02X", packet[pay]);
                i++;
            }
            printf("\n\n\n");
        }
    }
}
void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}
int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }
    char* interface = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);

    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", interface, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        //printf("%u bytes captured\n", header->caplen);
        print_packet(packet, header);
    }

    pcap_close(pcap);

}

