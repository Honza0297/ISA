#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#define DEFAULT_PORT 53
int err = 0;

#define ERR_ARGS -1

typedef struct {
    char* server;
    char* address;
    int port; // -p
    int recursion; // -r
    int reversion; // -x
    int aaa; // -6
} Input_args;

Input_args check_args(int argc, char** argv)
{
    int opt;
    Input_args input_args = { NULL, NULL, DEFAULT_PORT, 0, 0, 0};
    while (42)
    {
        static struct option long_options[] =
                {
                        {"r",   no_argument, 0, 'r'},
                        {"x",   no_argument, 0, 'x'},
                        {"6",   no_argument,    0, '6'},
                        {"s",   required_argument, 0, 's'},
                        {"p",   required_argument, 0, 'p'}, //default = 53
                        {0, 0, 0, 0}
                };
        int option_index = 0;
        opt = getopt_long_only (argc, argv, "rx6s:p:", long_options, &option_index);
        if(opt == -1)
            break;
        switch(opt)
        {
            case 0:
                printf("DUNNO WHAT GOING HERE\n"); //TODO
                break;
            case 'r':
                input_args.recursion = 1;
                break;
            case 'x':
                input_args.reversion = 1;
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
                err = ERR_ARGS;
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

int main(int argc, char** argv )
{
    Input_args input_args = check_args(argc,argv);
    if(err)
    {
       exit(err);
    }
    printf("rekurze: %d, reverze: %d, AAA: %d, server: %s, port: %d, adresa: %s\n", input_args.recursion, input_args.reversion, input_args.aaa, input_args.server, input_args.port, input_args.address);

       return 0;
}
