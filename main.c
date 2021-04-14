#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <ctype.h>

typedef struct {
    char *hostname;
    char server_ip[100];
    int fd;
}connection_info_t;

int resolve_hostname(char *hostname, char *ip) {
	struct hostent *he;
	struct in_addr **addr_list;

    he = gethostbyname(hostname);

	if (he == NULL) 
	{
		herror("gethostbyname");
        return -1;
	}
	addr_list = (struct in_addr **) he->h_addr_list;
	
	for(int i = 0; addr_list[i] != NULL; i++) 
	{
		strcpy(ip , inet_ntoa(*addr_list[i]));
	}
    return 1;
}

int create_socket(connection_info_t *server_info) {
    if (resolve_hostname(server_info->hostname, server_info->server_ip) == -1) {
        return -1;
    }

    int socket_desc = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(socket_desc == -1){
        return -1;
    }
    
    server_info->fd = socket_desc;

    return 0;
}

int start_connection(connection_info_t *server_info) {
    struct sockaddr_in server;

    inet_pton(AF_INET, server_info->server_ip, &server.sin_addr);
    server.sin_family = AF_INET;

    return connect(server_info->fd, (struct sockaddr *) &server, sizeof(server));
}

int send_message(connection_info_t *server_info, char *message, size_t message_size) {
    return send(server_info->fd , message, message_size, 0);
}

int fetch_message(connection_info_t *server_info, char *message, size_t message_size) {
    return recv(server_info->fd, message, message_size, 0);
}

int close_connection(connection_info_t *server_info) {
    return close(server_info->fd);
}

void print_help() {
    puts("Test");
}

int main (int argc, char **argv) {
    char *host = NULL;
    int index;
    int c;

    int nostop = 0;
    int count = 0;
    int size = 0;
    int timeout = 0;

    while ((c = getopt (argc, argv, "ic:s:t:")) != -1) {
        switch (c) {
            case 'h':
                host = optarg;
                break;
            case 'c':
                count = atoi(optarg);
                break;
            case 'i':
                nostop = 1;
                break;
            case 's':
                size = atoi(optarg);
                break;
            case 't':
                timeout = atoi(optarg);
                break;
            case '?':
                if (optopt == 'p' || optopt == 'h') {
                    fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                } else if (isprint (optopt)) {
                    fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                }
                return EXIT_FAILURE;
            default:
                abort ();
        }
    } 

    if (argc - optind == 1) {
        host = argv[optind];
    } else if (optind - argc == 0) {
        puts("Missing Address!");
        exit(EXIT_FAILURE);
    } else {
        for (index = optind + 1; index < argc; index++) {
            printf ("Bad parameter %s!\n", argv[index]);
        }
        exit(EXIT_FAILURE);
    }

    connection_info_t *info = malloc(sizeof(connection_info_t));
    info->hostname =  host;

    if (create_socket(info) == -1) {
        fprintf (stderr, "ERROR: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (start_connection(info) == -1) {
        fprintf (stderr, "ERROR: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    //print start info

    struct icmphdr hdr;
    memset(&hdr, 0, sizeof(struct icmphdr));
    hdr.type = ICMP_ECHO;

    while (count <= 0) {
        char data[9000];
        struct icmphdr rcv_hdr;

        hdr.un.echo.sequence++; 
        memcpy(data, &hdr, sizeof(struct icmphdr) + size);

        if (send_message(info, data, sizeof(struct icmphdr) + size) == -1) {
            fprintf (stderr, "ERROR: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }

        puts("PACKET SENT!");

        //deal with 127.0.0.1 pings
        if (fetch_message(info, data, sizeof(data)) == -1) {
            fprintf (stderr, "ERROR: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }

        //checksum

        memcpy(&rcv_hdr, data, sizeof(struct icmphdr));
        if (rcv_hdr.type == ICMP_ECHOREPLY) {
            printf("Reply, id=0x%x, sequence =  0x%x\n", rcv_hdr.un.echo.id, rcv_hdr.un.echo.sequence);
        } else {
            printf("ERROR: Got ICMP with type %x!\n", rcv_hdr.type);
            break;
        }

        //collect stats
        count--;
    }

    //final stats print
    return EXIT_SUCCESS;
}
