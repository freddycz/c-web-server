/*
** server.c -- a stream socket server demo
*/

#include <asm-generic/socket.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/poll.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <poll.h>

#define PORT "3000"  // the port users will be connecting to

#define BACKLOG 10   // how many pending connections queue will hold
#define MIN_REQ_SIZE 500 //in bytes 

#define MAX_METHOD_LEN 10
#define MAX_PATH_LEN 1024
#define MAX_PROTOCOL_LEN 9 

struct http_request {
    char method[MAX_METHOD_LEN];
    char path[MAX_PATH_LEN];
    char protocol[MAX_PROTOCOL_LEN];
};

void sigchld_handler(int s) {
    // waitpid() might overwrite errno, so we save and restore it:
    int saved_errno = errno;

    while(waitpid(-1, NULL, WNOHANG) > 0);

    errno = saved_errno;
}


// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int read_request(int fd, char **s, int *size) {
    int received = 0;
    *size = MIN_REQ_SIZE;
    *s = malloc(sizeof(char) * *size);
    if (*s == NULL) {
        return -1;
    }
    *s[0] = '\0';
    
    while(1) {
        int available = *size - received;
        if (available <= 0) {
            *size += MIN_REQ_SIZE;
            char *new_s = realloc(*s, *size);
            if (new_s == NULL) {
                free(*s);
                return -1;
            }
            *s = new_s;
            available += MIN_REQ_SIZE;
        }
        int got = recv(fd, *s+received, available, MSG_DONTWAIT);


        if (got < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
               break; 
            }
            free(*s);
            return -1; 
        }
        if (got == 0) {
            break;
        }

        received += got;
        *((*s)+received) = '\0';



        if (received >= 4 && strcmp(*s+received-4, "\r\n\r\n") == 0) {
            break;
        }
    }

    *size = received + 1;
    char *trimmed_s = realloc(*s, *size);
    if (trimmed_s != NULL) {
        *s = trimmed_s;
    }
    return 0;
}

int parse_request(struct http_request *req,char *req_str, int size) {
    int max_buf_size = MAX_METHOD_LEN + MAX_PATH_LEN + MAX_PROTOCOL_LEN;
    char buf[max_buf_size];

    int i, buf_size;

    for (i = 0; i < size && i < max_buf_size-1; i++) {
        if (req_str[i] == '\n') {
            break;
        }
        buf[i] = req_str[i];
    }
    buf_size = i;

    if (buf[buf_size-1] == '\r') {
        buf[buf_size-1] = '\0';
    } else {
        buf[buf_size] = '\0';
    }

    char *method = strtok(buf, " ");
    char *path = strtok(NULL, " ");
    char *protocol = strtok(NULL, " ");

    if (!method || !path || !protocol) return -1;

    strncpy(req->method, method, MAX_METHOD_LEN-1);
    strncpy(req->path, path, MAX_PATH_LEN-1);
    strncpy(req->protocol, protocol, MAX_PROTOCOL_LEN-1);

    return 0;
}

void send_error(int fd, int err) {
    if (err == 500) {
        char *interal_err = "HTTP/1.0 500 Internal Server Error";
        send(fd, interal_err, strlen(interal_err), 0);
    } else if (err == 501) {
        char *not_implemented = "HTTP/1.0 501 Not Implemented";
        send(fd, not_implemented, strlen(not_implemented), 0);
    } else if (err == 400) {
        char *bad_req = "HTTP/1.0 400 Bad Request";
        send(fd, bad_req, strlen(bad_req), 0);
    }
}

void handle_request(int fd) {
    char *req_str;
    int req_size = MIN_REQ_SIZE;

    int status;

    status = read_request(fd, &req_str, &req_size);

    if (status == -1) {
        printf("failed to read request\n");
        send_error(fd, 500);
        return;
    }


    struct http_request req;
    status = parse_request(&req, req_str, req_size); 
    free(req_str);

    if (status == -1) {
        printf("failed to parse request\n");
        send_error(fd, 400);
        return;
    }

    if (strcmp(req.method, "GET") == 0) {
        char *text = "HTTP/1.0 200 OK\nContent-Length: 122\nContent-Type: text/html; charset=utf-8\n\n";
        if (send(fd, text, strlen(text), 0) == -1)
            perror("send");
        char *content = "<!DOCTYPE html><html><title>HTML Tutorial</title><body><h1>This is a heading</h1><p>This is a paragraph.</p></body></html>";
        if (send(fd, content, strlen(content), 0) == -1)
            perror("send");
    } else {
        send_error(fd, 501);
        printf("Method not supported\n");
    }
}


int main(void) {
    int sockfd, new_fd;  // listen on sock_fd, new connection on new_fd
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr; // connector's address information
    socklen_t sin_size;
    struct sigaction sa;
    int yes=1;
    char s[INET6_ADDRSTRLEN];
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and bind to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
                sizeof(int)) == -1) {
            perror("setsockopt");
            exit(1);
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("server: bind");
            continue;
        }

        break;
    }

    freeaddrinfo(servinfo); // all done with this structure

    if (p == NULL)  {
        fprintf(stderr, "server: failed to bind\n");
        exit(1);
    }

    if (listen(sockfd, BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }

    sa.sa_handler = sigchld_handler; // reap all dead processes
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    printf("server: waiting for connections...\n");

    while(1) {  // main accept() loop
        sin_size = sizeof their_addr;
        new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
        if (new_fd == -1) {
            perror("accept");
            continue;
        }

        inet_ntop(their_addr.ss_family,get_in_addr((struct sockaddr *)&their_addr),
            s, sizeof s);
        printf("server: got connection from %s\n", s);

        if (!fork()) { // this is the child process
            close(sockfd); // child doesn't need the listener
            struct pollfd pfds[1]; // More if you want to monitor more
            pfds[0].fd = new_fd;          // Standard input
            pfds[0].events = POLLIN; // Tell me when ready to read
            
            int num_events = poll(pfds, 1, -1);
            if (num_events == -1) {
                printf("failed to poll\n");
                close(new_fd);
                exit(0);
            }
            int pollin_happened = pfds[0].revents & POLLIN;

            if (pollin_happened) {
                handle_request(new_fd);
            }
            
            close(new_fd);
            exit(0);
        }
        close(new_fd);  // parent doesn't need this
    }

    return 0;
}
