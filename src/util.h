/* util.h: libshout utility/portability functions */

#ifndef __LIBSHOUT_UTIL_H__
#define __LIBSHOUT_UTIL_H__

char *util_strdup(const char *s);
char *util_base64_encode(char *data);
int util_read_header(int sock, char *buff, unsigned long len);

#endif /* __LIBSHOUT_UTIL_H__ */
