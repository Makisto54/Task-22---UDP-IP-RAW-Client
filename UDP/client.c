#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <linux/ip.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <linux/udp.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define BUF_SIZE 255
#define DEST_PORT 0xAABB
#define SOURCE_PORT 0xBBAA
#define SERVER_ADDR "127.0.0.1"

void error_macro(const char *error)
{
    perror(error);
    exit(1);
}

int main(void)
{
    int val = 1;
    int address = 0;
    char *ptr = NULL;
    int socket_fd = 0;
    struct iphdr *ip = {0};
    struct udphdr *udp = {0};
    char buf[BUF_SIZE] = {0};
    struct sockaddr_in client = {0};
    struct sockaddr_in server = {0};
    char msg_buf[BUF_SIZE - 28] = {0};
    socklen_t client_socket_fd_size = 0;
    char ip_address[INET_ADDRSTRLEN] = {0};

    socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (socket_fd == -1)
    {
        error_macro("SOCKET CREATE");
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(0xAABB);
    int ret = inet_pton(AF_INET, SERVER_ADDR, &address);
    if (ret == -1 || ret == 0)
    {
        error_macro("INET PTON");
    }
    server.sin_addr.s_addr = address;

    if (setsockopt(socket_fd, IPPROTO_IP, IP_HDRINCL, &val, sizeof(val)) == -1)
    {
        error_macro("SETSOCKOPT");
    }

    client_socket_fd_size = sizeof(struct sockaddr_in);
    do
    {
        ptr = buf;
        bzero(buf, BUF_SIZE);
        bzero(msg_buf, BUF_SIZE - 28);
        bzero(ip_address, INET_ADDRSTRLEN);

        ip = (struct iphdr*)buf;

        ip->version = 4;
        ip->ihl = 5;
        ip->tos = 0;
        ip->ttl = 255;
        ip->frag_off = 0;
        ip->protocol = IPPROTO_UDP;
        ip->daddr = address;

        ptr += 20;

        udp = (struct udphdr*)(buf + sizeof(struct iphdr));

        udp->source = htons(SOURCE_PORT);
        udp->dest = htons(DEST_PORT);
        udp->len = htons(BUF_SIZE - sizeof(struct iphdr));
        udp->check = 0;

        ptr += 8;

        fgets(msg_buf, BUF_SIZE - 28, stdin);
        char *p = strchr(msg_buf, '\n');
        if (p != NULL)
        {
            msg_buf[strlen(msg_buf) - 1] = '\0';
        }
        memcpy(ptr, msg_buf, BUF_SIZE - 28);

        if (sendto(socket_fd, buf, BUF_SIZE, 0, (struct sockaddr *)&server,
            client_socket_fd_size) == -1)
        {
            error_macro("SEND ERROR");
        }

        for (;;)
        {
            if (recvfrom(socket_fd, buf, BUF_SIZE, 0, (struct sockaddr *)&client,
                &client_socket_fd_size) == -1)
            {
                error_macro("RECVFROM ERROR");
            }

            ip = (struct iphdr*)buf;
            udp = (struct udphdr*)(buf + sizeof(struct iphdr));

            if (NULL == inet_ntop(AF_INET, &ip->saddr, ip_address, INET_ADDRSTRLEN))
            {
                error_macro("INET NTOP");
            }

            if ((strncmp(SERVER_ADDR, ip_address, INET_ADDRSTRLEN) == 0) && ntohs(udp->dest) == SOURCE_PORT)
            {
                printf("Received Message - %s\n", (buf + sizeof(struct udphdr) + sizeof(struct iphdr)));
                break;
            }
        }
    } while (strncmp((buf + sizeof(struct udphdr) + sizeof(struct iphdr)), "exit", BUF_SIZE) != 0);

    return 0;
}
