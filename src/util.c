/* util.c: libshout utility/portability functions */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "util.h"

char *util_strdup(const char *s)
{
	if (!s) return NULL;
	return strdup(s);
}

int util_read_header(int sock, char *buff, unsigned long len)
{
    int read_bytes, ret;
    unsigned long pos;
    char c;

    read_bytes = 1;
    pos = 0;
    ret = 0;

    while ((read_bytes == 1) && (pos < (len - 1))) {
        read_bytes = 0;

        if ((read_bytes = recv(sock, &c, 1, 0))) {
            if (c != '\r') buff[pos++] = c;
            if ((pos > 1) && (buff[pos - 1] == '\n' && buff[pos - 2] == '\n')) {
                ret = 1;
                break;
            }
        } else {
            break;
        }
    }

    if (ret) buff[pos] = '\0';

    return ret;
}

static char base64table[64] = {
    'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
    'Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f',
    'g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v',
    'w','x','y','z','0','1','2','3','4','5','6','7','8','9','+','/'
};

/* This isn't efficient, but it doesn't need to be */
char *util_base64_encode(char *data)
{
    int len = strlen(data);
    char *out = malloc(len*4/3 + 4);
    char *result = out;
    int chunk;

    while(len > 0) {
        chunk = (len >3)?3:len;
        *out++ = base64table[(*data & 0xFC)>>2];
        *out++ = base64table[((*data & 0x03)<<4) | ((*(data+1) & 0xF0) >> 4)];
        switch(chunk) {
            case 3:
                *out++ = base64table[((*(data+1) & 0x0F)<<2) | ((*(data+2) & 0xC0)>>6)];
                *out++ = base64table[(*(data+2)) & 0x3F];
                break;
            case 2:
                *out++ = base64table[((*(data+1) & 0x0F)<<2)];
                *out++ = '=';
                break;
            case 1:
                *out++ = '=';
                *out++ = '=';
                break;
        }
        data += chunk;
        len -= chunk;
    }
    *out = 0;

    return result;
}

