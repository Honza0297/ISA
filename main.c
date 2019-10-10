#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>

#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <pcap.h>

#define DEFAULT_PORT 53
#define MAX_UDP_SEND 1
int err = 0;
pcap_t *pcap_handle;
#define ERR_ARGS -1
#define ERR_FILE -2

typedef struct {
    char* server;
    char* address;
    int port; // -p
    int recursion; // -r
    int reverse; // -x
    int aaa; // -6
} Input_args;
//Tato funkce neni mym dilem. Pro podrobnější informace si prosím prohlédněte dokumentaci.
uint16_t udp_checksum(const void *buff, size_t len, in_addr_t src_addr, in_addr_t dest_addr)
{
    const uint16_t *buf=buff;
    uint16_t *ip_src=(void *)&src_addr, *ip_dst=(void *)&dest_addr;
    uint32_t sum;
    size_t length=len;
    // Calculate the sum                                            //
    sum = 0;
    while (len > 1)
    {
        sum += *buf++;
        if (sum & 0x80000000)
            sum = (sum & 0xFFFF) + (sum >> 16);
        len -= 2;
    }
    if ( len & 1 )
        // Add the padding if the packet lenght is odd          //
        sum += *((uint8_t *)buf);
    // Add the pseudo-header                                        //
    sum += *(ip_src++);
    sum += *ip_src;
    sum += *(ip_dst++);
    sum += *ip_dst;
    sum += htons(IPPROTO_UDP);
    sum += htons(length);
    // Add the carries                                              //
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    // Return the one's complement of sum                           //
    return ( (uint16_t)(~sum)  );
}

Input_args check_args(int argc, char** argv)
{
    int opt;
    Input_args input_args = { NULL, NULL, DEFAULT_PORT, 0, 0, 0};
    while (42)
    {
        opt = getopt (argc, argv, "rx6s:p:");
        if(opt == -1)
            break;
        switch(opt)
        {
            case 'r':
                input_args.recursion = 1;
                break;
            case 'x':
                input_args.reverse = 1;
                break;
            case '6':
                input_args.aaa = 1;
                break;
            case 's':
                input_args.server = optarg;
                break;
            case 'p':
                input_args.port = (int) strtol(optarg, NULL, 10);
                break;
            default:
                fprintf(stderr, "Error: Unknown input argument. Please check your input.\n");
        }
    }
    if(optind < argc) {
        input_args.address = argv[optind];
    }

    if(!(input_args.server) || !(input_args.address))
    {
        fprintf(stderr, "Error: Please specify server (-s) and address.\n");
        err = ERR_ARGS;
    }
    return input_args;
}


//Tato funkce neni mym dilem. Pro podrobnější informace si prosím prohlédněte dokumentaci.
unsigned short csum(unsigned short *buf, int nwords)
{       //
    unsigned long sum;
    for(sum=0; nwords>0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);

}
int find_nameserver_string_prefix(const char *str)
{
    //todo test delky stringu
    char nameserver[] = "nameserver";
    int lenght = 10;
    int found = 0;
    for(int i = 0; i < lenght; i++)
    {
        if(str[i] != nameserver[i])
        {
            found = 0;
            break;
        }
        found = 1;
    }
    return found;
}

char* get_dst_addr()
{
    //TODO
    // ma se podivat do /etc/resolv.conf a tam si najit svuj DNS
    FILE *resolv_file = fopen( "/etc/resolv.conf", "r" );
    if(resolv_file == NULL)
    {
        fprintf(stderr, "Cannot open /etc/resolv.conf. Exiting...\n");
        exit(ERR_FILE);
    }
    char line[255];
    char *ip = malloc(sizeof(char)*15); //4*3 for bytes + 3 for dots
    for(int i = 0; i < 15; i++)
    {
        ip[i] = '\0';
    }
    while(fgets(line, 254, resolv_file))
    {
        if(find_nameserver_string_prefix(line))
        {
            //TODO tady resit v4 vs v6 - udelat funkce isv4 isv6 nebo tak...
            for(int i = 0; i < 15; i++)
            {
                if(line[i+11] == '\n' || line[i+10] == EOF)
                {
                    break;
                }
                else
                {
                    ip[i] = line[i+11];
                }
            }
            printf("IP is: %s\n", ip);
            break;
        }
   printf("%s", line);
    }

    if(fclose(resolv_file) != 0)
    {
        fprintf(stderr, "Cannot close /etc/resolv.conf. Continuing...\n");
    }
    return ip;
}

char* get_src_addr(char *interface_name, char *netmask)
{
    struct ifaddrs *interface_names = NULL;
    if(getifaddrs(&interface_names))
    {
        exit(44);
    }
    struct ifaddrs *head = interface_names;
    struct ifaddrs *backup = interface_names;


    int found = 0;
    struct sockaddr_in *temp_sockaddr;
    struct sockaddr_in *temp_mask;
    while(head != NULL)
    {
        if(strcmp(interface_name, head->ifa_name) == 0)
        {
            if(head->ifa_addr->sa_family == AF_INET || head->ifa_addr->sa_family == AF_INET6 )
            {
                found = 1;
                temp_sockaddr = (struct sockaddr_in*)head->ifa_addr;
                temp_mask = (struct sockaddr_in*)head->ifa_netmask;
                break;
            }
        }
        head = head->ifa_next;
    }
    if(!found)
    {
        exit(88); //TODO ERR CODE
    }
    char* src_addr = malloc(sizeof(char)*39);
    inet_ntop(AF_INET,&(temp_sockaddr->sin_addr), src_addr,39);
    inet_ntop(AF_INET,&(temp_mask->sin_addr), netmask,39);
    freeifaddrs(backup);
    return src_addr;
}
void set_udp_header(struct udphdr *udp, int source_port, int *dest_port, char *src_addr, char *dst_addr)
{
    udp->source= htons(source_port);
    udp->dest = htons(*dest_port);
    udp->len = htons(sizeof(struct udphdr));
    udp->check = udp_checksum(udp, sizeof(struct udphdr), inet_addr(src_addr), inet_addr(dst_addr));
}

void set_ip_header(struct ip *ip_header, char *src_addr, char *dst_addr, int size, int tcp)
{
    ip_header->ip_v = 4;
    ip_header->ip_hl = sizeof*ip_header >> 2;
    ip_header->ip_tos = 0;
    ip_header->ip_len = htons(size);//celkova velikost paketu
    ip_header->ip_id = htons(36458);
    ip_header->ip_off = htons(0);
    ip_header->ip_ttl = 255;
    if(tcp)
        ip_header->ip_p = IPPROTO_TCP;
    else
        ip_header->ip_p = IPPROTO_UDP;
    ip_header->ip_sum = 0;
    ip_header->ip_src.s_addr = inet_addr(src_addr);
    ip_header->ip_dst.s_addr = inet_addr(dst_addr);
    ip_header->ip_sum = csum((unsigned short *)ip_header, size);
}

void set_pcap_handle(char * interface_name,char *rule)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_handle = pcap_open_live(interface_name, 65500, 0, 100, errbuf);
    if(pcap_handle == NULL)
    {
        printf("ERR during creating pcap_handle");
        exit(45);
    }
    bpf_u_int32 pcap_mask;
    bpf_u_int32 pcap_net;
    pcap_lookupnet(interface_name, &pcap_net, &pcap_mask, errbuf);

    struct bpf_program *filter = (struct bpf_program *)malloc(sizeof(struct bpf_program));;
    pcap_compile(pcap_handle ,filter, rule, 0, pcap_net);
    if(err)
    {
        printf("err during pcap compile. %d", err);
        exit(46);
    }
    err = pcap_setfilter(pcap_handle,filter);
    if(err == -1)
    {
        printf("err during pcap set filter.");
        exit(47);
    }
}

void stop_pcap(int signal_number)
{
    pcap_breakloop(pcap_handle);
}

int main(int argc, char** argv )
{
    Input_args input_args = check_args(argc,argv);
    if(err)
    {
       exit(err);
    }
    fprintf(stderr, "rekurze: %d, reverze: %d, AAA: %d, server: %s, port: %d, adresa: %s\n", input_args.recursion, input_args.reverse, input_args.aaa, input_args.server, input_args.port, input_args.address);

    char * dst_addr = get_dst_addr();
    char *interface_name = "wlp2s0"; //or eth0 TODO spravne interface
    char *mask = malloc(sizeof(char)*39); //NOTE wtf?
    char* src_addr = get_src_addr(interface_name, mask);

    //Start of UDP scanning
    int *UDP_port = &input_args.port;
    char * string_UDP_port = malloc(sizeof(char)*5); //max port number = 65535
    sprintf(string_UDP_port, "%d", *UDP_port);



    int udp_packet_size = (sizeof(struct ip) + sizeof(struct udphdr)) * sizeof(char);
    char datagram[udp_packet_size];
    memset (datagram, 0, udp_packet_size);

    struct ip* ip_header = (struct ip*)datagram;
    struct udphdr*udp = (struct udphdr *) (datagram + sizeof(struct ip));

    set_ip_header(ip_header, src_addr, dst_addr, udp_packet_size, 0);

    //there are two implementations of udphdr, both do the same:
    // source/uh_sport
    // dest/uh_dport
    // len/uh_len
    //check/uh_sum
    set_udp_header(udp, 46666, UDP_port, src_addr, dst_addr);

    int one = 1;
    //setting socket

    int sock = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if(sock < 0)
    {

        exit(48);
    }

    int recvsock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(recvsock < 0)
    {
        exit(49);
    }
    if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
    {
        perror("setsockopt() error");
        exit(-1);
    }

    struct sockaddr_in sendto_addr;
    sendto_addr.sin_addr.s_addr = inet_addr(dst_addr); //dst address
    sendto_addr.sin_family = AF_INET;
    sendto_addr.sin_port = htons(46666); //UDP_port from which i send packets

    //prepare PCAP
    char rule[15] = "ip proto \\icmp"; //TODO WTF KURVA IS THIS???
    set_pcap_handle(interface_name, rule);

    //structures needed by PCAP
    struct pcap_pkthdr *header = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
    const  u_char *arrived_packet;

    if(sendto(sock, datagram, sizeof(datagram), 0, (struct sockaddr *)&sendto_addr, sizeof(sendto_addr)) < 0)
    {
        perror("sendto err\n");
    }

    int repeat = 0; //counter of repeated scan tries.
    while(42)
    {
        alarm(1);
        signal(SIGALRM, stop_pcap);
        arrived_packet = pcap_next(pcap_handle, header);
        if(arrived_packet)
        {
            struct ip*sniffed_ip = (struct ip*)(arrived_packet + 14); //14 == sizeof(sniff_eth)
            struct icmphdr* sniffed_icmp = (struct icmphdr*)(arrived_packet+14+sizeof(struct ip));
            char * s_ip = malloc(sizeof(char)*39);

            inet_ntop(AF_INET, &(sniffed_ip->ip_src), s_ip, 39);
            if(sniffed_icmp->type == 3 && sniffed_icmp->code == 3)
            {
                printf("%d udp: closed \n", *UDP_port);
                break;
            }
        }
        else
        {
            if(repeat == MAX_UDP_SEND)
            {
                printf("%d udp: open/filtered\n", *UDP_port);
                break;
            }
            else
            {
                repeat++;
                if(sendto(sock, datagram, sizeof(datagram), 0, (struct sockaddr *)&sendto_addr, sizeof(sendto_addr)) < 0)
                {
                    perror("sendto err\n");
                }
            }
        }
    }//end of while 42
    pcap_close(pcap_handle);

    return 0;
}
