#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

typedef struct {
    char* udp_range;
    char* tcp_range;
    char* interface_name;
    char* domname_or_ipaddr;
} Input_args;

Input_args check_args(int argc, char** argv)
{
    int opt;
    Input_args input_args = { NULL, NULL, NULL,NULL};
    while (42)
    {
        static struct option long_options[] =
                {
                        {"",   required_argument, 0, 'i'},
                        {"pt",  required_argument,    0, 't'},
                        {"pu",  required_argument, 0, 'u'}
                };
        int option_index = 0;
        opt = getopt_long_only (argc, argv, "i:u:t:", long_options, &option_index);
        if(opt == -1)
            break;
        switch(opt)
        {
            case 'i':
                input_args.interface_name = optarg;
                break;
            case 't':
                input_args.tcp_range = optarg;
                break;
            case 'u':
                input_args.udp_range = optarg;
                break;
            default:
                fprintf(stderr, "Error: Unknown input argument. Please check your input.\n");
        }
    }
    if(optind < argc) {
        input_args.domname_or_ipaddr = argv[optind]; //next arguments ignored
    }

    if(!((input_args.tcp_range || input_args.udp_range) && input_args.domname_or_ipaddr))
    {
        fprintf(stderr, "Error: Please specify udp range and/or tcp range and domain name or IP address.\n");
        err = ERR_ARGS;
    }
    return input_args;
}

int main(int argc, char** argv )
{
    Input_args input_args = check_args(argc,argv);
    if(err)
    {
       exit(-1);
    }
    
       return 0;
}
