#include "../util.h"

#ifdef __linux__
#include <string.h>

/*
 * Copy src to string dst of size siz.  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz == 0).
 * Returns strlen(src); if retval >= siz, truncation occurred.
 */
size_t
strlcpy(char *dst, const char *src, size_t dstlen)
{
	size_t srclen = strlen(src);

	if (dstlen > 0) {
		if (dstlen > srclen)
			strcpy(dst, src);
		else {
			strncpy(dst, src, dstlen - 1);
			dst[dstlen - 1] = 0;
		}
	}

	return srclen;
}
#endif
