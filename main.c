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
#include <signal.h>
#include <sys/poll.h>
#include <time.h>

#define DEFAULT_TIMEOUT 15
#define DEFAULT_COUNT 5
#define DEFAULT_DATA_SIZE 10

int keepSending = 1;

typedef struct {
    char *hostname;
    char server_ip[100];
    int fd;
}connection_info_t;

void sendHandler(int sig) {
    keepSending = 0;
}

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

uint16_t checksum(uint16_t *header, int len) {	
	uint16_t result = 0;
	uint32_t sum = 0;
	uint16_t odd_byte;
	
	while (len > 1) {
		sum += *header++;
		len -= 2;
	}
	
	if (len == 1) {
		*(uint8_t*)(&odd_byte) = * (uint8_t*)header;
		sum += odd_byte;
	}
	
	sum =  (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	result =  ~sum;
	
	return result; 
}

void print_help() {
    puts("Usage:");
    puts("sudo ./ping <target_address> <options>\n");
    puts("Options:");
    puts("-h        Show usage");
    puts("-i        continuous ping");
    puts("-c <int>  number of ICMP requests to send");
    puts("-s <int>  byte size of data");
    puts("-t <int>  timeout in sec\n");
}

int main (int argc, char **argv) {
    char *host = NULL;
    int index;
    int c;

    int nostop = 0;
    int count = DEFAULT_COUNT;
    int size = DEFAULT_DATA_SIZE;
    int timeout = DEFAULT_TIMEOUT;

    signal(SIGINT, sendHandler);

    while ((c = getopt (argc, argv, "hic:s:t:")) != -1) {
        switch (c) {
            case 'h':
                print_help();
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
                print_help();
                return EXIT_FAILURE;
            default:
                abort ();
        }
    } 

    if (argc - optind == 1) {
        host = argv[optind];
    } else if (optind - argc == 0) {
        puts("Destination address required!");
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

    printf("PING %s with %d bytes of data\n", info->server_ip, size);

    struct icmphdr hdr;
    memset(&hdr, 0, sizeof(struct icmphdr));
    hdr.type = ICMP_ECHO;
    hdr.un.echo.id = 4321;

    struct sockaddr_in addr;
    inet_pton(AF_INET, info->server_ip, &addr.sin_addr);
    addr.sin_family = AF_INET;

    int requests = 0;
    int responses = 0;
    struct sockaddr_in recv_addr;
    struct timespec time_start, time_end;
    unsigned char datagram[9000];
    struct icmphdr rcv_hdr;
    struct iphdr iphdr;
    struct pollfd p;
    int ret;

    while (keepSending) {
        hdr.un.echo.sequence++; 
        hdr.checksum = 0;

        memcpy(datagram, &hdr, sizeof(struct icmphdr));

        hdr.checksum = checksum((uint16_t *) datagram, sizeof(struct icmphdr) + size);

        memcpy(datagram, &hdr, sizeof(struct icmphdr));

        requests++;

        p.fd = info->fd;
        p.events = POLLIN;
        
        clock_gettime(CLOCK_MONOTONIC, &time_start);

        if (sendto(info->fd, datagram, sizeof(struct icmphdr) + size, 0, (struct sockaddr *) &addr, sizeof(struct sockaddr)) == -1) {
            fprintf (stderr, "ERROR: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }

        ret = poll(&p, 1, timeout * 1000);

        if (ret == -1) {
            fprintf(stderr, "ERROR: %s", strerror(errno));
            exit(EXIT_FAILURE);
        } else if (!ret) {
            printf ("Timeout!\n");
        }

        if (p.revents & POLLIN) {
            //deal with pings originating from 127.0.0.1 
            int r_addr_size = sizeof(recv_addr);
            if (recvfrom(info->fd, datagram, sizeof(datagram), 0, (struct sockaddr *) &recv_addr, &r_addr_size) == -1) {
                fprintf (stderr, "ERROR: %s\n", strerror(errno));
            }

            clock_gettime(CLOCK_MONOTONIC, &time_end);
        
            memcpy(&iphdr, datagram, sizeof(struct iphdr));
            memcpy(&rcv_hdr, datagram + sizeof(struct iphdr), sizeof(struct icmphdr));

            if (rcv_hdr.type == ICMP_ECHOREPLY) {
                //issue with negative time, sec might need to be taken into account
                printf("Reply from %s bytes=42+%d time=%dms ttl=%d seq=%d\n", inet_ntoa(recv_addr.sin_addr), size, (int)((time_end.tv_nsec-time_start.tv_nsec)*1e-6), iphdr.ttl, rcv_hdr.un.echo.sequence);
                responses++;
            } else {
                printf("ERROR: Got ICMP response with type %x!\n", rcv_hdr.type);
                exit(EXIT_FAILURE);
            }
        }

        sleep(1);

        count--;
        if (count <= 0 && !nostop) {
            break;
        }
    }

    printf("\n----- %s ping stats -----\n", inet_ntoa(recv_addr.sin_addr));
    printf("%d packets sent, %d response received, %d%% packet loss\n", requests, responses, (int)((1 - responses/(float)requests)*100));
    return EXIT_SUCCESS;
}
