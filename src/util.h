/* util.h: libshout utility/portability functions */

#ifndef __LIBSHOUT_UTIL_H__
#define __LIBSHOUT_UTIL_H__

/* String dictionary type, without support for NULL keys, or multiple
 * instances of the same key */
typedef struct _util_dict {
  char *key;
  char *val;
  struct _util_dict *next;
} util_dict;

char *util_strdup(const char *s);

util_dict *util_dict_new(void);
void util_dict_free(util_dict *dict);
/* dict, key must not be NULL. */
int util_dict_set(util_dict *dict, const char *key, const char *val);
const char *util_dict_get(util_dict *dict, const char *key);
char *util_dict_urlencode(util_dict *dict, char delim);

char *util_base64_encode(char *data);
char *util_url_encode(const char *data);
int util_read_header(int sock, char *buff, unsigned long len);

#endif /* __LIBSHOUT_UTIL_H__ */
