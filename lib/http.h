#pragma once
#include <netinet/in.h>
#include <stdint.h>

#define HTTP_PORT 80
#define HTTP_MAX_LINE 1024

typedef struct http_message {
    char *method;
    char *path;
    char *version;
    char *body;
};

typedef struct http_response {
    uint16_t code;
    char *message;
};
