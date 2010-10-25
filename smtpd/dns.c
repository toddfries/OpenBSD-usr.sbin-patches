/*	$OpenBSD: dns.c,v 1.23 2010/09/08 13:32:13 gilles Exp $	*/

/*
 * Copyright (c) 2008 Gilles Chehade <gilles@openbsd.org>
 * Copyright (c) 2009 Jacek Masiulaniec <jacekm@dobremiasto.net>
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
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/stat.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>

#include <event.h>
#include <netdb.h>
#include <resolv.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "smtpd.h"

void	dns_setup(void);
int	dns_resolver_updated(void);
struct dnssession *dnssession_init(struct smtpd *, struct dns *);
void	dnssession_destroy(struct smtpd *, struct dnssession *);
void	dnssession_mx_insert(struct dnssession *, struct mx *);
void	dns_asr_handler(int, short, void *);
void	dns_asr_mx_handler(int, short, void *);
void	lookup_host(struct imsgev *, struct dns *, int, int);
void	lookup_mx(struct imsgev *, struct dns *);
void	lookup_ptr(struct imsgev *, struct dns *);

struct asr *asr = NULL;

/*
 * User interface.
 */

void
dns_query_host(struct smtpd *env, char *host, int port, u_int64_t id)
{
	struct dns	 query;

	bzero(&query, sizeof(query));
	strlcpy(query.host, host, sizeof(query.host));
	query.port = port;
	query.id = id;

	imsg_compose_event(env->sc_ievs[PROC_LKA], IMSG_DNS_HOST, 0, 0, -1,
	    &query, sizeof(query));
}

void
dns_query_mx(struct smtpd *env, char *host, int port, u_int64_t id)
{
	struct dns	 query;

	bzero(&query, sizeof(query));
	strlcpy(query.host, host, sizeof(query.host));
	query.port = port;
	query.id = id;

	imsg_compose_event(env->sc_ievs[PROC_LKA], IMSG_DNS_MX, 0, 0, -1, &query,
	    sizeof(query));
}

void
dns_query_ptr(struct smtpd *env, struct sockaddr_storage *ss, u_int64_t id)
{
	struct dns	 query;

	bzero(&query, sizeof(query));
	query.ss = *ss;
	query.id = id;

	/* we need to construct a PTR query */
	switch (ss->ss_family) {
	case AF_INET: {
		in_addr_t addr;
		
		addr = ((struct sockaddr_in *)ss)->sin_addr.s_addr;

		bsnprintf(query.host, sizeof(query.host),
		    "%d.%d.%d.%d.in-addr.arpa",
		    (addr >> 24) & 0xff,
		    (addr >> 16) & 0xff,
		    (addr >> 8) & 0xff,
		    addr & 0xff);
		break;
	}
	case AF_INET6: {
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)ss;
		struct in6_addr	*in6_addr;

		in6_addr = &in6->sin6_addr;
		bsnprintf(query.host, sizeof(query.host),
		    "%d.%d.%d.%d.%d.%d.%d.%d.%d.%d.%d.%d.%d.%d.%d.%d."
		    "%d.%d.%d.%d.%d.%d.%d.%d.%d.%d.%d.%d.%d.%d.%d.%d."
		    "ip6.arpa",
		    in6_addr->s6_addr[15] & 0xf,
		    (in6_addr->s6_addr[15] >> 4) & 0xf,
		    in6_addr->s6_addr[14] & 0xf,
		    (in6_addr->s6_addr[14] >> 4) & 0xf,
		    in6_addr->s6_addr[13] & 0xf,
		    (in6_addr->s6_addr[13] >> 4) & 0xf,
		    in6_addr->s6_addr[12] & 0xf,
		    (in6_addr->s6_addr[12] >> 4) & 0xf,
		    in6_addr->s6_addr[11] & 0xf,
		    (in6_addr->s6_addr[11] >> 4) & 0xf,
		    in6_addr->s6_addr[10] & 0xf,
		    (in6_addr->s6_addr[10] >> 4) & 0xf,
		    in6_addr->s6_addr[9] & 0xf,
		    (in6_addr->s6_addr[9] >> 4) & 0xf,
		    in6_addr->s6_addr[8] & 0xf,
		    (in6_addr->s6_addr[8] >> 4) & 0xf,
		    in6_addr->s6_addr[7] & 0xf,
		    (in6_addr->s6_addr[7] >> 4) & 0xf,
		    in6_addr->s6_addr[6] & 0xf,
		    (in6_addr->s6_addr[6] >> 4) & 0xf,
		    in6_addr->s6_addr[5] & 0xf,
		    (in6_addr->s6_addr[5] >> 4) & 0xf,
		    in6_addr->s6_addr[4] & 0xf,
		    (in6_addr->s6_addr[4] >> 4) & 0xf,
		    in6_addr->s6_addr[3] & 0xf,
		    (in6_addr->s6_addr[3] >> 4) & 0xf,
		    in6_addr->s6_addr[2] & 0xf,
		    (in6_addr->s6_addr[2] >> 4) & 0xf,
		    in6_addr->s6_addr[1] & 0xf,
		    (in6_addr->s6_addr[1] >> 4) & 0xf,
		    in6_addr->s6_addr[0] & 0xf,
		    (in6_addr->s6_addr[0] >> 4) & 0xf);
		break;
	}
	default:
		fatalx("dns_query_ptr");
	}

	imsg_compose_event(env->sc_ievs[PROC_LKA], IMSG_DNS_PTR, 0, 0, -1, &query,
	    sizeof(query));
}

/* LKA interface */
int
dns_resolver_updated(void)
{
	struct stat sb;
	static time_t mtime = 0;

	/* first run, we need a resolver context */
	if (mtime == 0)
		return 1;

	if (stat(_PATH_RESCONF, &sb) < 0) {
		log_warnx("dns_resolver_updated: please check %s",
			_PATH_RESCONF);
		return 0;
	}

	/* no change since last time */
	if (mtime == sb.st_mtime)
		return 0;

	/* resolv.conf has been updated */
	mtime = sb.st_mtime;
	return 1;
}

void
dns_setup(void)
{
	if (asr)
		asr_done(asr);

	asr = asr_resolver(NULL);
	if (asr == NULL)
		log_warnx("dns_setup: unable to initialize resolver, please check /etc/resolv.conf");
}

void
dns_async(struct smtpd *env, struct imsgev *asker, int type, struct dns *query)
{
	struct dnssession *dnssession;

	if (dns_resolver_updated())
		dns_setup();

	if (asr == NULL) {
		log_warnx("dns_async: resolver is disabled, please check %s",
		    _PATH_RESCONF);
		goto noasr;
	}

	query->env   = env;
	query->type  = type;
	query->asker = asker;
	dnssession = dnssession_init(env, query);
	
	switch (type) {
	case IMSG_DNS_PTR:
		dnssession->aq = asr_query_dns(asr, T_PTR, C_IN, query->host, 0);
		break;
	case IMSG_DNS_HOST:
		dnssession->aq = asr_query_host(asr, query->host, PF_UNSPEC);
		break;
	case IMSG_DNS_MX:
		dnssession->aq = asr_query_dns(asr, T_MX, C_IN, query->host, 0);
		break;
	default:
		goto err;
	}
	/* query and set up event to handle answer */
	if (dnssession->aq == NULL)
		goto err;
	dns_asr_handler(-1, -1, dnssession);
	return;

err:
	log_debug("dns_async: ASR error while attempting to resolve `%s'",
	    query->host);
	dnssession_destroy(env, dnssession);

noasr:
	query->error = EAI_AGAIN;
	if (type != IMSG_DNS_PTR)
		type = IMSG_DNS_HOST_END;
	imsg_compose_event(asker, type, 0, 0, -1, query, sizeof(*query));
}

void
dns_asr_handler(int fd, short event, void *arg)
{
	struct dnssession *dnssession = arg;
	struct dns *query = &dnssession->query;
	struct smtpd *env = query->env;
	struct packed pack;
	struct header	h;
	struct query	q;
	struct rr rr;
	struct sockaddr_in *in;
	struct sockaddr_in6 *in6;
	struct asr_result ar;
	struct timeval tv = { 0, 0 };
	char *p;
	int cnt;

	query->error = EAI_AGAIN;
	if (event == EV_TIMEOUT)
		goto err;

	switch (asr_run(dnssession->aq, &ar)) {
	case ASR_NEED_READ:
		tv.tv_usec = ar.ar_timeout * 1000;
		event_set(&dnssession->ev, ar.ar_fd, EV_READ,
		    dns_asr_handler, dnssession);
		event_add(&dnssession->ev, &tv);
		return;

	case ASR_NEED_WRITE:
		tv.tv_usec = ar.ar_timeout * 1000;
		event_set(&dnssession->ev, ar.ar_fd, EV_WRITE,
		    dns_asr_handler, dnssession);
		event_add(&dnssession->ev, &tv);
		return;

	case ASR_DONE:
		break;
	}

	if (ar.ar_err) {
		/* XXX should be the case, but just to be sure. eric@ */
		ar.ar_data = NULL;
		goto err;
	}

	packed_init(&pack, ar.ar_data, ar.ar_datalen);
	if (unpack_header(&pack, &h) < 0 || unpack_query(&pack, &q) < 0)
		goto err;

	if (h.ancount == 0) {
		query->error = EAI_NONAME;
		goto err;
	}

	switch (query->type) {
	case IMSG_DNS_PTR:
		if (h.ancount > 1) {
			log_debug("dns_asr_handler: PTR query returned several answers.");
			log_debug("dns_asr_handler: keeping only first result.");
		}
		if (unpack_rr(&pack, &rr) < 0)
			goto err;
		free(ar.ar_data);

		print_dname(rr.rr.ptr.ptrname, query->host, sizeof (query->host));
		if ((p = strrchr(query->host, '.')) != NULL)
			*p = '\0';

		query->error = 0;
		imsg_compose_event(query->asker, IMSG_DNS_PTR, 0, 0, -1, query,
		    sizeof(*query));
		dnssession_destroy(env, dnssession);
		break;

	case IMSG_DNS_HOST:
		cnt = h.ancount;
		for (; cnt; cnt--) {
			if (unpack_rr(&pack, &rr) < 0)
				goto err;

			if (rr.rr_type == T_A) {
				query->ss.ss_len = sizeof(struct sockaddr_in);
				query->ss.ss_family = AF_INET;
				in = (struct sockaddr_in *)&query->ss;
				in->sin_addr = rr.rr.in_a.addr;
			}
			else if (rr.rr_type == T_AAAA) {
				query->ss.ss_len = sizeof(struct sockaddr_in6);
				query->ss.ss_family = AF_INET6;
				in6 = (struct sockaddr_in6 *)&query->ss;
				in6->sin6_addr = rr.rr.in_aaaa.addr6;
			}

			query->error = 0;
			imsg_compose_event(query->asker, IMSG_DNS_HOST, 0, 0, -1,
			    query, sizeof(*query));
		}
		free(ar.ar_data);
		imsg_compose_event(query->asker, IMSG_DNS_HOST_END, 0, 0, -1,
		    query, sizeof(*query));
		dnssession_destroy(env, dnssession);
		break;

	case IMSG_DNS_MX: {
		struct mx mx;

		cnt = h.ancount;
		for (; cnt; cnt--) {
			if (unpack_rr(&pack, &rr) < 0)
				goto err;

			print_dname(rr.rr.mx.exchange, mx.host, sizeof (mx.host));
			if ((p = strrchr(mx.host, '.')) != NULL)
				*p = '\0';
			mx.prio =  rr.rr.mx.preference;

			/* sorted insert that will not overflow MAX_MX_COUNT */
			dnssession->mxarraysz = h.ancount - cnt;
			if (dnssession->mxarraysz > MAX_MX_COUNT)
				dnssession->mxarraysz = MAX_MX_COUNT;
			dnssession_mx_insert(dnssession, &mx);
		}
		free(ar.ar_data);

		/* The T_MX scenario is a bit trickier than T_PTR and T_A lookups.
		 * Rather than forwarding the answers to the process that queried,
		 * we retrieve a set of MX hosts ... that need to be resolved. The
		 * loop above sorts them by priority, all we have left to do is to
		 * perform T_A lookups on all of them sequentially and provide the
		 * process that queried with the answers.
		 *
		 * To make it easier, we do this in another handler.
		 *
		 * -- gilles@
		 */
		dnssession->mxcurrent = &dnssession->mxarray[0];
		dnssession->aq = asr_query_dns(asr, T_A, C_IN,
		    dnssession->mxcurrent->host, 0);
		if (dnssession->aq == NULL)
			goto err;

		dns_asr_mx_handler(-1, -1, dnssession);
		break;
	}

	default:
		fatalx("unknown dns query type");
	}
	return;

err:
	free(ar.ar_data);
	if (query->type != IMSG_DNS_PTR)
		query->type = IMSG_DNS_HOST_END;
	imsg_compose_event(query->asker, query->type, 0, 0, -1, query,
	    sizeof(*query));
	dnssession_destroy(env, dnssession);
}


/* only handle MX requests */
void
dns_asr_mx_handler(int fd, short event, void *arg)
{
	struct dnssession *dnssession = arg;
	struct dns *query = &dnssession->query;
	struct smtpd *env = query->env;
	struct packed pack;
	struct header	h;
	struct query	q;
	struct rr rr;
	struct sockaddr_in *in;
	struct sockaddr_in6 *in6;
	struct asr_result ar;
	struct timeval tv = { 0, 0 };
	int cnt;

	query->error = EAI_AGAIN;
	if (event == EV_TIMEOUT)
		goto err;

	switch (asr_run(dnssession->aq, &ar)) {
	case ASR_NEED_READ:
		tv.tv_usec = ar.ar_timeout * 1000;
		event_set(&dnssession->ev, ar.ar_fd, EV_READ,
		    dns_asr_mx_handler, dnssession);
		event_add(&dnssession->ev, &tv);
		return;

	case ASR_NEED_WRITE:
		tv.tv_usec = ar.ar_timeout * 1000;
		event_set(&dnssession->ev, ar.ar_fd, EV_WRITE,
		    dns_asr_mx_handler, dnssession);
		event_add(&dnssession->ev, &tv);
		return;

	case ASR_DONE:
		break;
	}

	if (ar.ar_err) {
		/* XXX should be the case, but just to be sure. eric@ */
		ar.ar_data = NULL;
		goto err;
	}

	packed_init(&pack, ar.ar_data, ar.ar_datalen);
	if (unpack_header(&pack, &h) < 0 ||
	    unpack_query(&pack, &q) < 0)
		goto err;

	if (h.ancount == 0) {
		query->error = EAI_NONAME;
		goto err;
	}

	cnt = h.ancount;
	for (; cnt; cnt--) {
		if (unpack_rr(&pack, &rr) < 0)
			goto err;

		if (rr.rr_type == T_A) {
			query->ss.ss_len = sizeof(struct sockaddr_in);
			query->ss.ss_family = AF_INET;
			in = (struct sockaddr_in *)&query->ss;
			in->sin_addr = rr.rr.in_a.addr;
		}
		else if (rr.rr_type == T_AAAA) {
			query->ss.ss_len = sizeof(struct sockaddr_in6);
			query->ss.ss_family = AF_INET6;
			in6 = (struct sockaddr_in6 *)&query->ss;
			in6->sin6_addr = rr.rr.in_aaaa.addr6;
		}

		query->error = 0;
		imsg_compose_event(query->asker, IMSG_DNS_HOST, 0, 0, -1, query,
		    sizeof(*query));
	}
	free(ar.ar_data);

	if (dnssession->mxcurrent == &dnssession->mxarray[dnssession->mxarraysz - 1]) {
		imsg_compose_event(query->asker, IMSG_DNS_HOST_END, 0, 0, -1,
		    query, sizeof(*query));
		dnssession_destroy(env, dnssession);
		return;
	}

	dnssession->mxcurrent++;
	dnssession->aq = asr_query_dns(asr, T_A, C_IN,
	    dnssession->mxcurrent->host, 0);
	if (dnssession->aq == NULL)
		goto err;
	dns_asr_mx_handler(-1, -1, dnssession);

	return;

err:
	free(ar.ar_data);
	imsg_compose_event(query->asker, IMSG_DNS_HOST_END, 0, 0, -1, query,
	    sizeof(*query));
	dnssession_destroy(env, dnssession);
	return;
}

struct dnssession *
dnssession_init(struct smtpd *env, struct dns *query)
{
	struct dnssession *dnssession;

	dnssession = calloc(1, sizeof(struct dnssession));
	if (dnssession == NULL)
		fatal("dnssession_init: calloc");

	dnssession->id = query->id;
	dnssession->query = *query;
	SPLAY_INSERT(dnstree, &env->dns_sessions, dnssession);
	return dnssession;
}

void
dnssession_destroy(struct smtpd *env, struct dnssession *dnssession)
{
	SPLAY_REMOVE(dnstree, &env->dns_sessions, dnssession);
	free(dnssession);
}

void
dnssession_mx_insert(struct dnssession *dnssession, struct mx *mx)
{
        size_t i;
        size_t j;
	
        if (dnssession->mxarraysz == 0) {
                dnssession->mxarray[0] = *mx;
                return;
        }

        for (i = 0; i < dnssession->mxarraysz; ++i)
                if (mx->prio < dnssession->mxarray[i].prio)
                        goto insert;

        if (i < MAX_MX_COUNT)
                dnssession->mxarray[i] = *mx;
        return;

insert:
        for (j = dnssession->mxarraysz; j > i; --j)
                dnssession->mxarray[j] = dnssession->mxarray[j - 1];
        dnssession->mxarray[i] = *mx;
}

int
dnssession_cmp(struct dnssession *s1, struct dnssession *s2)
{
	/*
	 * do not return u_int64_t's
	 */
	if (s1->id < s2->id)
		return (-1);

	if (s1->id > s2->id)
		return (1);

	return (0);
}

SPLAY_GENERATE(dnstree, dnssession, nodes, dnssession_cmp);
