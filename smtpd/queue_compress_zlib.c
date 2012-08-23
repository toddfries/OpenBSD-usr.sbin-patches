#include <sys/types.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <ctype.h>
#include <err.h>
#include <fcntl.h>
#include <imsg.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <zlib.h>

#include "smtpd.h"
#include "log.h"


struct queue_compress_backend	queue_compress_zlib = {
	queue_compress_zlib_file,
	queue_uncompress_zlib_file,
	queue_compress_zlib_buffer,
	queue_uncompress_zlib_buffer
};


static int
mktmpfile(void)
{
	char	 path[MAXPATHLEN];
	int	 fd;

#define PATH_TMP		"/tmp"

	if (ckdir(PATH_TMP, 0700, env->sc_pw->pw_uid, 0, 0) == 0)
		errx(1, "error in /tmp directory setup");

	if (! bsnprintf(path, sizeof(path), "%s/zlib.XXXXXXXXXX", PATH_TMP))
		err(1, "snprintf");

	if ((fd = mkstemp(path)) == -1)
		err(1, "cannot create temporary file %s", path);

	unlink(path);

	return (fd);
}

int
queue_compress_zlib_file(int fdin, int fdout)
{
	gzFile	gzfd;
	char	buf[8192];
	int	r, w;

	if (fdin == -1 || fdout == -1)
		return (-1);

	gzfd = gzdopen(fdout, "wb");

	while ((r = read(fdin, buf, sizeof(buf)))) {
		if (r == -1)
			return (0);

		w = gzwrite(gzfd, buf, r);
		if (w == 0 || w != r)
			return (0);
	}
	gzclose(gzfd);

	return (1);
}

int
queue_uncompress_zlib_file(int fd)
{
	gzFile	 gzfd;
	int	 outfd;
	int	 r, w;
	char	 buf[8192];

	if (fd == -1)
		return (-1);

	outfd = mktmpfile();

	gzfd = gzdopen(fd, "r");
	while ((r = gzread(gzfd, buf, sizeof(buf)))) {

		if (r == -1)
			return (0);

		w = write(outfd, buf, r);

		if (w == -1 || w != r)
			return (0);
	}
	
	return (outfd);
}

size_t
queue_compress_zlib_buffer(char *inbuf, size_t inbuflen, char *outbuf, size_t outbuflen)
{
	uLong	compress_bound;
	int	ret;

	compress_bound = compressBound((uLongf) inbuflen);

	if (compress_bound > outbuflen)
		return (0);

	ret = compress((Bytef *) outbuf, (uLongf *) &outbuflen,
		 (const Bytef *) inbuf, (uLong) inbuflen);

	return (ret == Z_OK ? outbuflen : 0);
}

size_t
queue_uncompress_zlib_buffer(char *inbuf, size_t inbuflen, char *outbuf, size_t outbuflen)
{
	int	ret;

	ret = uncompress((Bytef *) outbuf, (uLongf *) &outbuflen,
	    (const Bytef *) inbuf, (uLong) inbuflen);

	return (ret == Z_OK ? outbuflen : 0);
}
