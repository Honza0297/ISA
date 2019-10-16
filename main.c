#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>


#include "structures.h"

#define DEFAULT_PORT 53
#define A 1
#define AAAA 28
#define CNAME 5
#define NS 2

#define IPv4 0
#define DOMNAME  1
#define IPv6 2
#define NOT_AN_IP -1

#define NOT_IMPLEMENTED 90
#define ERR_ARGS -1
#define ERR_FILE -2
#define ERR_SOCKET -3

#define FORMAT_ERR 1
#define SERVER_FAIL 2
#define NAME_ERR 3
#define RC_NOT_IMPLEMENTED 4
#define REFUSED 5


void process_error(int return_code, char * err_string)
{
    fprintf(stderr, "Something has happened, the program will be terminated. Error message is shown below: \n");
    fprintf(stderr, "%s \n", err_string);
    exit(return_code);
}

Input_args check_args(int argc, char** argv)
{
    int opt;
    Input_args input_args = { NULL, NULL, DEFAULT_PORT, 0, 0, 0, 0};
    while (42)
    {
        opt = getopt (argc, argv, "rx6s:p:h");
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
            case 'h':
                input_args.help = 1;
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
     process_error(ERR_ARGS, strerror(errno));
    }
    return input_args;
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
    FILE *resolv_file = fopen( "/etc/resolv.conf", "r" );
    if(resolv_file == NULL)
    {
        process_error(ERR_FILE, strerror(errno));
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
            break;
        }
    }

    if(fclose(resolv_file) != 0)
    {
        fprintf(stderr, "Cannot close /etc/resolv.conf. Continuing...\n");
    }
    return ip;
}

void  add_numbers_to_hostname(unsigned char* hostname, unsigned char *dest_str)
{
    unsigned char buffer[64]; //max lenght of part of domain name separated by dots
    unsigned int bufferend = 0;
    unsigned int dest_end = 0;
    for(unsigned long i = 0; i < strlen((char *)hostname); i++)
    {
        if(hostname[i] == '.')
        {
            dest_str[dest_end] = bufferend;
            dest_str[dest_end+1] = '\0';
            dest_end = strlen((const char *)dest_str);
            for(unsigned int j = 0; j < bufferend; j++)
            {
                dest_str[dest_end] = buffer[j];
                dest_str[dest_end+1] = '\0';
                dest_end++;
                buffer[j] = '\0';
            }
            bufferend = 0;
        } else{
            buffer[bufferend] = hostname[i];
            bufferend++;
        }
    }
    dest_str[dest_end] = bufferend;
    dest_str[dest_end+1] = '\0';
    dest_end = strlen((const char *)dest_str);
    for(unsigned int j = 0; j < bufferend; j++)
    {
        dest_str[dest_end] = buffer[j];
        dest_end++;
        buffer[j] = '\0';
    }
    dest_str[dest_end] = '\0';
}

void remove_numbers_from_hostname(unsigned char *hostname, unsigned char *new_hostname)
{
    for(int i = 0; i < (int)strlen((const char *)hostname); i++)
    {
        unsigned char num_of_chars = hostname[i];
        for(int j = 0; j < num_of_chars; j++)
        {
            new_hostname[i] = hostname[i+1];
            i++;
        }
        new_hostname[i] = '.';
        new_hostname[i+1] = '\0';
    }
    new_hostname[strlen((const char *)hostname)-1] = '\0';
}


//TODO TOTO NENI MOJE, UPRAV TO!
u_char* ReadName(unsigned char* reader,unsigned char* buffer,int* count)
{
    unsigned char *name;
    unsigned int p=0,jumped=0,offset;
    int i , j;

    *count = 1;
    name = (unsigned char*)malloc(256);

    name[0]='\0';

    //read the names in 3www6google3com format
    while(*reader!=0)
    {
        if(*reader>=192)
        {
            offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000 ;)
            reader = buffer + offset - 1;
            jumped = 1; //we have jumped to another location so counting wont go up!
        }
        else
        {
            name[p++]=*reader;
        }

        reader = reader+1;

        if(jumped==0)
        {
            *count = *count + 1; //if we havent jumped to another location then we can count up
        }
    }

    name[p]='\0'; //string complete
    if(jumped==1)
    {
        *count = *count + 1; //number of steps we actually moved forward in the packet
    }

    //now convert 3www6google3com0 to www.google.com
    for(i=0;i<(int)strlen((const char*)name);i++)
    {
        p=name[i];
        for(j=0;j<(int)p;j++)
        {
            name[i]=name[i+1];
            i=i+1;
        }
        name[i]='.';
    }
    name[i-1]='\0'; //remove the last dot
    //printf("name is: %s\n", name);
    return name;
}

char *get_type_descriptor(unsigned short type) {
    switch(ntohs(type))
    {
        case A:
            return "A";
        case AAAA:
            return "AAAA";
        case CNAME:
            return "CNAME";
        case NS:
            return "NS";
        default:
            return "Not a standard type";
    }
}

char *get_class_string(unsigned short dns_class) {
    return ntohs(dns_class) == 1 ? "IN" : "not-IN"; //TODO pridat podporu? nitpick
}

void print_help()
{
    printf("*********** Simple DNS resolver ***********\n"
           "Usage: dns [-r] [-x] [-6] -s server [-p port] adresa\n\n"
           "Flags:\n"
    "    -r: Recursion desired. If not set, recursion set in DNS header is 0.\n"
    "    -x: Reverse query enabled.\n"
    "    -6: Query type AAAA instead of default A.\n"
    "    -s: IP address or domain name of nameserver where to send query.\n"
    "    -p port: Port number where to send query, default is 53.\n\n"
    "Usage examples:\n"
    "    $ dns -r -s kazi.fit.vutbr.cz www.fit.vut.cz\n"
    "Possible output:\n"
    "      Authoritative: No, Recursive: Yes, Truncated: No\n"
    "      Question section (1)\n"
    "      www.fit.vut.cz., A, IN\n"
    "      Answer section (1)\n"
    "      www.fit.vut.cz., A, IN, 14400, 147.229.9.26\n"
    "      Authority section (0)\n"
    "      Additional section (0)\n");
}
int check_server(char * server)
{
    int ret;
    char *fakebuffer[256];
    if(inet_pton(AF_INET, server, fakebuffer))
    {
        ret = IPv4;
    }
    else if(inet_pton(AF_INET6, server, fakebuffer))
    {
        ret = IPv6;
    }
    else
    {
        ret = NOT_AN_IP;
    }
    return ret;
}

void get_interface_name(char *interface)
{
    /*
     * Function return string with that interface, which rceived the most packets
     */
    struct ifaddrs *ifaddrs;

    getifaddrs(&ifaddrs);
    struct ifaddrs *temp =ifaddrs;
    unsigned int max_rx_packets = 0;
    unsigned int *current_rx_packets; //todo vypsat jak jsem na to prisel...
    char temp_interface[16];
    for(int i = 0; i < (int)strlen(temp_interface); i++)
    {
        temp_interface[i] = '\0';
    }

    while(temp != NULL)
    {
        if(!temp->ifa_data)
        {
            temp = temp->ifa_next;
            continue;
        }
        current_rx_packets = (unsigned int*)temp->ifa_data;
        if(max_rx_packets < *current_rx_packets)
        {
            max_rx_packets = *current_rx_packets;
            int i = 0;
            for(i = 0; i < (int)strlen(temp->ifa_name); i++)
            {
                temp_interface[i] = temp->ifa_name[i];
            }
            temp_interface[i] = '\0';
        }

        temp = temp->ifa_next;
    }
    freeifaddrs(ifaddrs);
    for(int i = 0; i < (int)strlen(temp_interface); i++)
    {
        interface[i] = temp_interface[i];
    }

}

void set_DNS_header(Input_args input_args, DNS_header *dns)
{
    dns->ID = htons(666); //TODO pouzit neco podle ceho identifikuju paket
    dns->is_query = 0; // query yes
    dns->opcode = 0;
    dns->authoritative_answer = 0;
    dns->truncated = 0; //not truncated
    dns->recursion_desired = input_args.recursion ? 1 : 0; //recursion according to input args (1 yes; 0 no)
    dns->recursion_available = 0;
    dns->future = 0; // if this would be the future, the project should be already done... :(
    dns->response_code = 0;
    dns->qcount = htons(1); //only one question
    dns->addcount = 0;
    dns->ancount = 0;
    dns->nscount = 0;
}

char * server_error_message(int server_error)
{
    switch(server_error)
    {
        case FORMAT_ERR:
            return "Server returned 1: Format error.";
        case SERVER_FAIL:
            return "Server returned 2: Server failure.";
        case NAME_ERR:
            return "Server returned 3: Name error.";
        case RC_NOT_IMPLEMENTED:
            return "Server returned 4: Function not implemented.";
        case REFUSED:
            return "Server returned 5: Refused.";
        default:
            return "Not-well-known error.";
    }
}

void set_socket_address(int family, in_addr_t addr, int port, struct sockaddr_in *sockaddr)
{
    sockaddr->sin_family = family;
    sockaddr->sin_addr.s_addr = addr; //dst address
    sockaddr->sin_port = port;
}

void ask_for_dns_ip(Input_args *input_args)
{
    char *dst_addr = get_dst_addr();
    char interface_name[16]; //Max interface name len according to
    get_interface_name(interface_name); //used interface is that interface, which received the most packets

    int *UDP_port = &input_args->port;
    char * string_UDP_port = malloc(sizeof(char)*5); //max port number = 65535
    sprintf(string_UDP_port, "%d", *UDP_port);

    int udp_packet_size = 655;
    char datagram[udp_packet_size];
    memset (datagram, 0, udp_packet_size);
    //setting socket

    int sock = socket(PF_INET, SOCK_DGRAM /*SOCK_RAW*/, IPPROTO_UDP);
    if(sock < 0)
    {
        process_error(ERR_SOCKET, strerror(errno));
    }

    struct sockaddr_in where_to_send;
    set_socket_address(AF_INET,inet_addr(dst_addr), htons(input_args->port), &where_to_send );

    DNS_header *dns = (DNS_header *)&datagram;
    set_DNS_header(*input_args, dns);

    unsigned char *qname = (unsigned char *)&datagram[sizeof(DNS_header)];
    add_numbers_to_hostname((unsigned char *)input_args->server, qname);

    DNS_query *query = (DNS_query *) &datagram[sizeof(DNS_header)+(strlen((const  char *)qname) +1)];
    query->qtype = htons(A); //1 means A, TODO AAA types etc
    query->qclass = htons(1); // 1 means "internet". Just do it.

    if(sendto(sock, datagram, sizeof(DNS_header) + (strlen((const char*)qname)+1) + sizeof(DNS_query), 0, (struct sockaddr *)&where_to_send, sizeof(where_to_send)) < 0)
    {
        perror("sendto err\n");
    }
    int size = sizeof(where_to_send);


    for(int i = 0; i < udp_packet_size; i++)
    {
        datagram[i] = '\0';
    }

    if(recvfrom (sock,(char*)datagram , udp_packet_size , 0 , (struct sockaddr*)&where_to_send , (socklen_t*)&size) < 0) //todo timeout?
    {
        process_error(ERR_SOCKET, strerror(errno));
    }


    dns = (DNS_header*)datagram;

    if(dns->response_code)
    {
        process_error((int)dns->response_code,server_error_message((int)dns->response_code) );
    }

    unsigned char *reader_head = (unsigned char *)&datagram[sizeof(DNS_header) + (strlen((const char*)qname)+1)];
    reader_head += + sizeof(DNS_query);

//TODO odsud jen kopcim!!!
    DNS_Answer answers[dns->ancount];
    int relative_index = 0; //relative index into reader head;

    //Start parsing answers
    for(int i = 0; i < ntohs(dns->ancount); i++)
    {
        answers[i].name = ReadName(reader_head,(unsigned char *)datagram,&relative_index); //just need to move...
        reader_head += relative_index;

        answers[i].info = (DNS_R_DATA_INFO *) reader_head;
        reader_head += sizeof(DNS_R_DATA_INFO);

        int IP_type =  ntohs(answers[i].info->type); //TODO rename
        int data_len = ntohs(answers[i].info->rdata_len);

        if(IP_type == 1) //TODO 1 nahradit za vhodné macro, jinak to znamená "pokud ipv4"
        {
            answers[i].response_data = (unsigned char *)malloc(sizeof(unsigned  char) * data_len);
            for(int j = 0; j < data_len; j++)
            {
                answers[i].response_data[j] = reader_head[0];
                reader_head++;
            }
            where_to_send.sin_addr.s_addr=(*(long*)answers[i].response_data); //working without ntohl
            input_args->server = inet_ntoa(where_to_send.sin_addr);
            return;
        }
        else //CNAME for example
        {
            ReadName(reader_head,(unsigned char *)datagram,&relative_index);
            reader_head +=relative_index;
        }
    }

}

void print_answer(DNS_Answer *record, int is_answer)
{
    printf("%s, %s, %s, %d, ", record->name, get_class_string(record->info->_class), get_type_descriptor(record->info->type), ntohl(record->info->ttl));
    unsigned short type = ntohs(record->info->type);
    if(is_answer)
    {
        if(type == A) //IPv4 address
        {
            char buffer[33];
            inet_ntop(AF_INET, record->response_data, buffer, 32);
            printf("%s",buffer);
        }
        if(type == NS || type == CNAME)
        {
            //Canonical name for an alias
            printf("%s",record->response_data);
        }
        if(type == AAAA)
        {
            char buffer[100];
            inet_ntop(AF_INET6, record->response_data, buffer, 99);
            printf("%s",buffer);
        }
    }
    printf("\n");
}

int main(int argc, char** argv )
{

    Input_args input_args = check_args(argc,argv);

    if(input_args.help)
    {
        print_help();
        return 0;
    }

    //check if server is DN or IP
    //TODO IPv6
    char * dst_addr;
    if(check_server(input_args.server) == NOT_AN_IP)
    {
        ask_for_dns_ip(&input_args);
    }

    dst_addr = input_args.server; //address of nameserver where to send queries


    char interface_name[16]; //Max interface name len according to
    get_interface_name(interface_name); //used interface is that interface, which received the most packets

    int *UDP_port = &input_args.port;
    char * string_UDP_port = malloc(sizeof(char)*5); //max port number = 65535
    sprintf(string_UDP_port, "%d", *UDP_port);


    int udp_packet_size = 655;
    char datagram[udp_packet_size];
    memset (datagram, 0, udp_packet_size);
    //setting socket

    int sock = socket(PF_INET, SOCK_DGRAM /*SOCK_RAW*/, IPPROTO_UDP);
    if(sock < 0)
    {
        process_error(ERR_SOCKET, strerror(errno));
    }



    //TODO comment this
    struct sockaddr_in where_to_send;
    set_socket_address(AF_INET, inet_addr(dst_addr),htons(input_args.port), &where_to_send);
    DNS_header *dns = (DNS_header *)&datagram;
    set_DNS_header(input_args, dns);


    unsigned char *qname = (unsigned char *)&datagram[sizeof(DNS_header)];
    add_numbers_to_hostname((unsigned char*)input_args.address, qname);
    DNS_query *query = (DNS_query *) &datagram[sizeof(DNS_header)+(strlen((const  char *)qname) +1)];
    query->qtype = htons(A); //1 means A, TODO AAA types etc
    query->qclass = htons(1); // 1 means "internet". Just do it.

    if(sendto(sock, datagram, sizeof(DNS_header) + (strlen((const char*)qname)+1) + sizeof(DNS_query), 0, (struct sockaddr *)&where_to_send, sizeof(where_to_send)) < 0)
    {
        perror("sendto err\n");
    }
    int size = sizeof(where_to_send);



    for(int i = 0; i < udp_packet_size; i++)
    {
        datagram[i] = '\0';
    }

    if(recvfrom (sock,(char*)datagram , udp_packet_size , 0 , (struct sockaddr*)&where_to_send , (socklen_t*)&size) < 0) //todo timeout?
    {
        process_error(ERR_SOCKET, strerror(errno));
    }


    dns = (DNS_header*)datagram;

    if(dns->response_code)
    {
        process_error((int)dns->response_code,server_error_message((int)dns->response_code) );
    }
    printf("Authoritative: %s, Recursive: %s, Truncated: %s\n", dns->authoritative_answer ? "Yes " : "No",dns->recursion_desired? "Yes" : "No",dns->truncated ? "Yes" : "No");

    unsigned char *reader_head = (unsigned char *)&datagram[sizeof(DNS_header) + (strlen((const char*)qname)+1)];
    DNS_query *received_question = (DNS_query *)reader_head;
    //SECTION printing question info
    printf("Question section (%d):\n", ntohs(dns->qcount));
    for(int i = 0; i < ntohs(dns->qcount);i++)
    {
        unsigned char* qname_without_numbers = (unsigned char*)malloc(sizeof(unsigned char) * strlen((const char *)qname));

        remove_numbers_from_hostname(qname, qname_without_numbers);
        printf("%s, %s, %s\n", qname_without_numbers, get_class_string(received_question->qclass), get_type_descriptor(received_question->qtype));
    }
    reader_head += + sizeof(DNS_query);

    DNS_Answer answers;
    int relative_index = 0; //relative index into reader head;
    printf("Answer Section (%d)\n" , ntohs(dns->ancount));
    //Start parsing answers
    for(int i = 0; i < ntohs(dns->ancount); i++)
    {
        answers.name = ReadName(reader_head,(unsigned char *)datagram,&relative_index);
        reader_head += relative_index;

        answers.info = (DNS_R_DATA_INFO *) reader_head;
        reader_head += sizeof(DNS_R_DATA_INFO);

        int IP_type =  ntohs(answers.info->type); //TODO rename
        int data_len = ntohs(answers.info->rdata_len);

        if(IP_type == 1) //TODO 1 nahradit za vhodné macro, jinak to znamená "pokud ipv4"
        {
            answers.response_data = (unsigned char *)malloc(sizeof(unsigned  char) * data_len);
            for(int j = 0; j < data_len; j++)
            {
                answers.response_data[j] = reader_head[0];
                reader_head++;

            }
            answers.response_data[data_len] = '\0'; //correct ending

        }
        else //CNAME for example
        {
           answers.response_data = ReadName(reader_head,(unsigned char *)datagram,&relative_index);
           reader_head +=relative_index;
        }
        print_answer(&answers, 1);
    }


    DNS_Answer authoritatives[dns->nscount];
    for(int i = 0; i < ntohs(dns->nscount); i++)
    {
        authoritatives[i].name = ReadName(reader_head,(unsigned char *)datagram,&relative_index);
        reader_head +=relative_index;

        authoritatives[i].info = (DNS_R_DATA_INFO *) reader_head;
        reader_head += sizeof(DNS_R_DATA_INFO);

        authoritatives[i].response_data = ReadName(reader_head,(unsigned char *)datagram,&relative_index);
        reader_head +=relative_index;
    }

    DNS_Answer additionals[dns->addcount];

    for(int i = 0; i < ntohs(dns->addcount); i++)
    {
       additionals[i].name = ReadName(reader_head,(unsigned char *)datagram,&relative_index);
       reader_head +=relative_index;

        additionals[i].info = (DNS_R_DATA_INFO *) reader_head;
        reader_head += sizeof(DNS_R_DATA_INFO);

        int response_type =  ntohs(additionals[i].info->type);
        int data_len = ntohs(additionals[i].info->rdata_len);

        if(response_type == A || response_type == AAAA)
        {
            additionals[i].response_data = (unsigned char *)malloc(data_len);
            for(int j = 0; j < data_len; j++)
            {
                additionals[i].response_data[j] = reader_head[0];
                reader_head++;
            }

           additionals[i].response_data[data_len] = '\0'; //correct ending
        }
        else //CNAME for example
        {
            additionals[i].response_data = ReadName(reader_head,(unsigned char *)datagram,&relative_index);
            reader_head +=relative_index;
        }
    }


    //print authorities
    printf("Authoritive Records (%d):\n" , ntohs(dns->nscount));
    for( int i=0 ; i < ntohs(dns->nscount) ; i++)
    {
        print_answer(&authoritatives[i], 1);
    }

    //print additional resource records
    printf("Additional Records (%d):\n" , ntohs(dns->addcount));
    for( int i=0; i < ntohs(dns->addcount) ; i++)
    {
        print_answer(&additionals[i], 1);
    }
    return 0;
}


