#include <asm-generic/socket.h>
#include <errno.h>
#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <strings.h>
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

#define BACKLOG 10   // how many pending connections queue will hold
#define MIN_REQ_SIZE 500 //in bytes 
#define MAX_FILE_SIZE 10 //in decimal places

#define MAX_METHOD_LEN 10 // max length of http method
#define MAX_PATH_LEN 1024 // max length of requested path
#define MAX_PROTOCOL_LEN 9 //max length of http protocol

char *port = NULL;
char *target_folder = NULL;

struct http_request {
    char method[MAX_METHOD_LEN];
    char path[MAX_PATH_LEN];
    char protocol[MAX_PROTOCOL_LEN];
};

void sigchld_handler(int s) {
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

int sendall(int soc, char *buf, int len) {
    int sent = 0;        
    int bytesleft = len;
    int n;

    while (sent < len) {
        n = send(soc, buf+sent, bytesleft, 0);
        if (n == -1) { 
            break; 
        }
        sent += n;
        bytesleft -= n;
    }

    return n==-1?-1:0; 
} 

char *get_file_ext(char *path) {
    char *p = NULL;

    for (p = path; *p != '\0'; p++) {
        if (*p == '.') {
            return p+1;
        }
    }
    return NULL;
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
        sendall(fd, interal_err, strlen(interal_err));
    } else if (err == 501) {
        char *not_implemented = "HTTP/1.0 501 Not Implemented";
        sendall(fd, not_implemented, strlen(not_implemented));
    } else if (err == 400) {
        char *bad_req = "HTTP/1.0 400 Bad Request";
        sendall(fd, bad_req, strlen(bad_req));
    }
}

char *get_file(char *path, int *file_len) {
    char *buf = NULL;
    FILE *f = fopen(path, "rb");

    if (f) {
        if (fseek(f, 0, SEEK_END) != 0) {
            return buf;
        }
        long len = ftell(f);

        if (fseek(f, 0, SEEK_SET) != 0) {
            return buf;
        }

        buf = malloc(len+1);
        if (buf == NULL) {
            return buf;
        }

        if (fread(buf, 1, len, f) != len) {
            free(buf);
            return NULL;
        }
        if (fclose(f) != 0) {
            free(buf);
            return NULL;
        }
        buf[len] = '\0';
        *file_len = (int) len;
    }

    return buf;
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
    printf("Request: %s %s\n", req.method, req.path);

    if (strcmp(req.method, "GET") == 0) {
        int path_len = strlen(target_folder) + strlen(req.path);
        int is_root = strcmp(req.path, "/");
        if (is_root == 0) {
            path_len += strlen("index.html");
        }
        char path[path_len+1];
        strcpy(path, target_folder);
        strcat(path, req.path);
        if (is_root == 0) {
            strcat(path, "index.html");
        }

        int file_len = 0;
        char *f = get_file(path, &file_len);
        

        if (f == NULL) {
            char *not_found = "HTTP/1.0 404 Not Found";
            if (sendall(fd, not_found, strlen(not_found)) == -1)
                perror("send");
            return;
        }

        char *head = "HTTP/1.0 200 OK\n";
        char content_len_header[MAX_FILE_SIZE+19] = "Content-Length: ";

        int dec_places = (int) log10((double) file_len)+1;
        if (dec_places > MAX_FILE_SIZE) {
            return;
        }
        char len_string[dec_places+1];
        sprintf(len_string, "%d", file_len);
        strcat(content_len_header, len_string);
        strcat(content_len_header, "\n\n");

        char *file_ext = get_file_ext(path);

        if (sendall(fd, head, strlen(head)) == -1)
            perror("send");
        if (strcmp(file_ext, "svg") == 0) {
            char *content_type = "Content-Type: image/svg+xml; charset=utf-8\n";
            if (sendall(fd, content_type, strlen(content_type)) == -1)
                perror("send");
        }
        if (sendall(fd, content_len_header, strlen(content_len_header)) == -1)
            perror("send");
        if (sendall(fd, f, file_len) == -1)
            perror("send");
        free(f);
    } else {
        send_error(fd, 501);
        printf("Method not supported\n");
    }
}

void new_server(char *new_port, char *folder) {
    free(port);
    port = NULL;
    port = malloc(strlen(new_port) + 1);
    strcpy(port, new_port);
    free(target_folder);
    target_folder = NULL;
    target_folder = malloc(strlen(folder) + 1);
    strcpy(target_folder, folder);

    int sockfd, new_fd;  
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr; 
    socklen_t sin_size;
    struct sigaction sa;
    int yes=1;
    char s[INET6_ADDRSTRLEN];
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if ((rv = getaddrinfo(NULL, port, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return; 
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

    freeaddrinfo(servinfo); 

    if (p == NULL)  {
        fprintf(stderr, "server: failed to bind\n");
        exit(1);
    }

    if (listen(sockfd, BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }

    sa.sa_handler = sigchld_handler; 
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    printf("server: waiting for requests...\n");

    while(1) {  
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
            struct pollfd pfds[1]; 
            pfds[0].fd = new_fd;  
            pfds[0].events = POLLIN; 
            
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
        close(new_fd); 
    }
}
