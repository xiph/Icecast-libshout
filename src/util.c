/* util.c: libshout utility/portability functions */

#include <stdio.h>
#include <string.h>

#include "util.h"

char *util_strdup(const char *s)
{
	if (!s) return NULL;
	return strdup(s);
}
