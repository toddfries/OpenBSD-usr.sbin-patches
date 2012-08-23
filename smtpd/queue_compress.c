/*
 * Copyright (c) 2012 Charles Longeau <chl@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

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
