#include <sys/types.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <imsg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "smtpd.h"

extern struct queue_compress_backend queue_compress_zlib;

struct queue_compress_backend *
queue_compress_backend_lookup(const char *name)
{
	if (!strcmp(name, "zlib"))
		return &queue_compress_zlib;

	/* if (!strcmp(name, "bzip")) */
	/* 	return &queue_compress_bzip; */

	/* if (!strcmp(name, "7zip")) */
	/* 	return &queue_compress_7zip; */

	return (NULL);
}

int
queue_compress_file(int fdin, int fdout)
{
	return env->sc_queue_compress->compress_file(fdin, fdout);
}

int
queue_uncompress_file(int fd)
{
	return env->sc_queue_compress->uncompress_file(fd);
}

size_t
queue_compress_buffer(char *ib, size_t iblen, char *ob, size_t oblen)
{
	return env->sc_queue_compress->compress_buffer(ib, iblen, ob, oblen);
}

size_t
queue_uncompress_buffer(char *ib, size_t iblen, char *ob, size_t oblen)
{
	return env->sc_queue_compress->uncompress_buffer(ib, iblen, ob, oblen);
}
