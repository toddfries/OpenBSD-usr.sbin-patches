/*
 * Copyright (c) 2010 Eric Faurot <eric@openbsd.org>
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

#include <err.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "asr.h"
#include "dnsutil.h"

struct kv { int code; const char *name; };


struct kv kv_family[] = {
	{ AF_UNIX,	"unix" },
	{ AF_INET,	"inet" },
	{ AF_INET6,	"inet6" },
	{ AF_IMPLINK,	"implink" },
	{ AF_BLUETOOTH,	"bluetooth" },
	{ 0,	NULL, }
};
struct kv kv_socktype[] = {
	{ SOCK_STREAM,	"stream" },
	{ SOCK_DGRAM,	"dgram" },
	{ SOCK_RAW,	"raw" },
	{ 0,	NULL, }
};
struct kv kv_protocol[] = {
	{ IPPROTO_UDP, "udp" },
	{ IPPROTO_TCP, "tcp" },
	{ 0,	NULL, }
};

static const char *
kv_lookup_name(struct kv *kv, int code)
{
	while (kv->name) {
		if (kv->code == code)
			return (kv->name);
		kv++;
	}
	return "???";
}

static int
kv_lookup_code(struct kv *kv, const char *name)
{
	while (kv->name) {
		if (!strcmp(name, kv->name))
			return (kv->code);
		kv++;
	}
	return -1;
}

static void
print_addrinfo(struct addrinfo *ai)
{
	char	buf[256];

	printf("   %s %s %s %s %s\n",
		kv_lookup_name(kv_family, ai->ai_family),
		kv_lookup_name(kv_socktype, ai->ai_socktype),
		kv_lookup_name(kv_protocol, ai->ai_protocol),
		print_addr(ai->ai_addr, buf, sizeof buf),
		ai->ai_canonname);
}

static void
usage(void)
{
	extern const char * __progname;

	fprintf(stderr, "usage: %s [-CHSPa] [-f family] [-p proto] "
		"[-s servname]\n	[-t socktype] [host...]\n", __progname);
	exit(1);
}

int
main(int argc, char *argv[])
{
	struct asr		*asr = NULL;
	struct asr_query	*aq;
	struct asr_result	 ar;
	struct addrinfo		*res, hints;
	char			*servname = NULL;
	int			 i, ch, aflag = 0;

	memset(&hints, 0, sizeof hints);

	while((ch = getopt(argc, argv, "CHPSaf:p:s:t:")) !=  -1) {
		switch(ch) {
		case 'C':
			hints.ai_flags |= AI_CANONNAME;
			break;
		case 'H':
			hints.ai_flags |= AI_NUMERICHOST;
			break;
		case 'P':
			hints.ai_flags |= AI_PASSIVE;
			break;
		case 'S':
			hints.ai_flags |= AI_NUMERICSERV;
			break;
		case 'a':
			aflag = 1;
			break;
		case 'f':
			i = kv_lookup_code(kv_family, optarg);
			if (i == -1)
				usage();
			hints.ai_family = i;
			break;
		case 'p':
			i = kv_lookup_code(kv_protocol, optarg);
			if (i == -1)
				usage();
			hints.ai_protocol = i;
			break;
		case 's':
			servname = optarg;
			break;
		case 't':
			i = kv_lookup_code(kv_socktype, optarg);
			if (i == -1)
				usage();
			hints.ai_socktype = i;
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	for(i = 0; i < argc; i++) {

		if (i)
			printf("\n");
		printf("ADDRINFO \"%s\"\n", argv[i]);

		if (aflag) {
			ar.ar_err = getaddrinfo(argv[i][0] ? argv[i]:NULL, servname, &hints, &ar.ar_ai);
			ar.ar_errstr = gai_strerror(ar.ar_err);
			ar.ar_count = 0;
			for (res = ar.ar_ai; res; res = res->ai_next)
				ar.ar_count += 1;
		} else {
			if (asr == NULL)
				asr = asr_resolver(NULL);
			if (asr == NULL)
				errx(1, "asr_resolver");
			aq = asr_query_addrinfo(asr, argv[i][0]?argv[i]:NULL, servname, &hints);
			if (aq == NULL)
				errx(1, "asr_query_addrinfo");
			asr_run_sync(aq, &ar);
		}
		if (ar.ar_err)
			printf("   ERROR: \"%s\"\n", ar.ar_errstr);
		else {
			for (res = ar.ar_ai; res; res = res->ai_next)
				print_addrinfo(res);
			freeaddrinfo(ar.ar_ai);
			printf("	FOUND: %i\n", ar.ar_count);
		}
	}

	if (asr)
		asr_done(asr);

	return (0);
}
