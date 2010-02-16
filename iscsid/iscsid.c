/*	$OpenBSD$ */

/*
 * Copyright (c) 2009 Claudio Jeker <claudio@openbsd.org>
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
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>

#include <err.h>
#include <event.h>
#include <fcntl.h>
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "iscsid.h"
#include "log.h"

void		main_sig_handler(int, short, void *);
__dead void	usage(void);


int
main(int argc, char *argv[])
{
	struct event ev_sigint, ev_sigterm, ev_sighup;
	struct passwd *pw;
	struct initiator *i;
	const char *ip = "127.0.0.1";
	const char *port = "3260";
	int ch, debug = 0;

	log_init(1);    /* log to stderr until daemonized */

	while ((ch = getopt(argc, argv, "dn:")) != -1) {
		switch (ch) {
		case 'd':
			debug = 1;
			break;
		case 'n':
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	/* XXX hack for now to do config less startup */
	if (argc > 2)
		usage();
	if (argc > 0) {
		ip = *argv++;
		argc--;
	}
	if (argc > 0) {
		port = *argv++;
		argc--;
	}

	/* check for root privileges  */
	if (geteuid())
		errx(1, "need root privileges");

	log_init(debug);
	if (!debug)
		daemon(1, 0);
	log_info("startup");

	event_init();
	vscsi_open("/dev/vscsi0");

	/* chroot and drop to iscsid user */
	if ((pw = getpwnam(ISCSID_USER)) == NULL)
		errx(1, "unknown user %s", ISCSID_USER);

	if (chroot(pw->pw_dir) == -1)
		fatal("chroot");
	if (chdir("/") == -1)
		fatal("chdir(\"/\")");
	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("can't drop privileges");

	/* setup signal handler */
	signal_set(&ev_sigint, SIGINT, main_sig_handler, NULL);
	signal_set(&ev_sigterm, SIGTERM, main_sig_handler, NULL);
	signal_set(&ev_sighup, SIGHUP, main_sig_handler, NULL);
	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);
	signal_add(&ev_sighup, NULL);
	signal(SIGPIPE, SIG_IGN);

	i = initiator_init();
	session_new(i, ip, port);

	event_dispatch();

	/* CLEANUP XXX */
	log_info("exiting.");
	return 0;
}

/* ARGSUSED */
void
main_sig_handler(int sig, short event, void *arg)
{
	/* signal handler rules don't apply, libevent decouples for us */
	switch (sig) {
	case SIGTERM:
	case SIGINT:
	case SIGHUP:
		event_loopexit(NULL);
		break;
	default:
		fatalx("unexpected signal");
		/* NOTREACHED */
	}
}

__dead void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-dv] [-n vscsi] hostname port\n",
	    __progname);
	exit(1);
}

int
parse_host(struct sockaddr_storage *sa, const char *s, const char *p)
{
	struct addrinfo	hints, *res;
	int rv;

	bzero(&hints, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST;
	if ((rv = getaddrinfo(s, p, &hints, &res)) == 0) {
		if (sizeof(*sa) < res->ai_addrlen)
			fatalx("parse_host: bork bork bork");
		bcopy(res->ai_addr, sa, res->ai_addrlen);
		freeaddrinfo(res);
		return 0;
	}

	log_warn("parse_host: %s", gai_strerror(rv));
	return -1;
}

int
socket_setblockmode(int fd, int nonblocking)
{
	int     flags;

	if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
		return -1;

	if (nonblocking)
		flags |= O_NONBLOCK;
	else
		flags &= ~O_NONBLOCK;     

	if ((flags = fcntl(fd, F_SETFL, flags)) == -1)
		return -1;
	return 0;
}
