//
// Created by jaberan on 16/10/2019.
//

#ifndef ISA_STRUCTURES_H
#define ISA_STRUCTURES_H


typedef struct {
    char* server;
    char* address;
    int port; // -p
    int recursion; // -r
    int reverse; // -x
    int aaa; // -6
    int help; // help :)
} Input_args;

typedef struct  { //order matters!!!!
    unsigned short ID; // unsigned short == :16

    char recursion_desired :1;
    char truncated :1; // in query it is zero
    char authoritative_answer :1; // in query it is zero
    char opcode :4; // 0 = standard query
    char is_query :1;

    char response_code :4; // 0 = no err, 1 = format err, 2 = server err, 3 = name err (domain name does not exist), 4 = type of query not implemented, 5 = refused; 0 in query
    char future :3; // zero
    char recursion_available :1; //0

    unsigned short qcount; // number of entries in question section, should be 1
    unsigned short ancount; // number of resource records in answer; 0 in query
    unsigned short nscount; // number of name server resource record; 0 in query
    unsigned short addcount; // number of resource records in additional record section, in query = 0

} DNS_header;

typedef struct {
    //QNAME???
    unsigned short qtype;
    unsigned short qclass;
} DNS_query;

#pragma pack(push, 1)
typedef struct {
    unsigned short type; //type of record in RDATA in "two octets" format 0x0001 = A, 0x0005 = CNAME and more
    unsigned short _class; //type of _class in  RDATA, (0x0001 - internet adddres)
    unsigned int ttl; //BEWARE, I suppose 4-byte int
    unsigned short rdata_len;
}DNS_R_DATA_INFO;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
    unsigned char *name;
    DNS_R_DATA_INFO *info;
    unsigned char * response_data;
} DNS_Answer;
#pragma pack(pop)
#endif //ISA_STRUCTURES_H
