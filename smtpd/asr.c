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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "asr.h"
#include "dnsutil.h"

#define DEFAULT_CONFFILE	"/etc/resolv.conf"
#define DEFAULT_HOSTFILE	"/etc/hosts"
#define DEFAULT_CONF		"lookup bind file\nameserver 127.0.0.1\n"
#define DEFAULT_LOOKUP		"lookup bind file"

#define ASR_MAXNS	5
#define ASR_MAXDB	3
#define ASR_MAXDOM	10

enum asr_query_type {
	ASR_QUERY_DNS,
	ASR_QUERY_HOST,
	ASR_QUERY_ADDRINFO
};

enum asr_db_type {
	ASR_DB_FILE,
	ASR_DB_DNS,
	ASR_DB_YP,
};

struct asr_db {
	int	 ad_type;
	char	*ad_path;
	int	 ad_timeout;
	int	 ad_retries;
	int	 ad_count;
	struct sockaddr *ad_sa[ASR_MAXNS];
};

struct asr {
	int		 a_refcount;
	int		 a_ndots;
	char		*a_domain;
	int		 a_domcount;
	char		*a_dom[ASR_MAXDOM];
	int		 a_dbcount;
	struct asr_db	 a_db[ASR_MAXDB];
};

struct asr_acache {
	struct asr_acache	*aa_next;
	union {
		struct sockaddr		any;
		struct sockaddr_in	in;
		struct sockaddr_in6	in6;
	} aa_sa;
};

struct asr_query {

	struct asr		*aq_asr;
	int			 aq_type;
	int			 aq_flags;
	int			 aq_state;

	int			 aq_timeout;
	int			 aq_fd;

	int			 aq_dom_idx;
	int			 aq_db_idx;
	int			 aq_ns_idx;
	int			 aq_ns_cycles;

	/* for dns */
	char 			*aq_fqdn;   /* the fqdn being looked for */
	struct query		 aq_query;
	uint16_t		 aq_reqid;
	char			 aq_opkt[PACKET_MAXLEN];
	size_t			 aq_opktlen;
	void			*aq_pktin;
	size_t			 aq_pktlen;
	struct packed		 aq_packed;
	int			 aq_nanswer;

	/* for host */
	char			*aq_host;
	int			 aq_family;
	int			 aq_count;
	FILE			*aq_file;

	/* for addrinfo */
	char			*aq_hostname;
	char			*aq_servname;
	struct addrinfo		 aq_hints;
	int			 aq_match_idx;
	struct asr_acache	*aq_addrcache;
	struct asr_acache	*aq_addrcachelast;
	int			 aq_noinet;
	int			 aq_noinet6;
	struct asr_query	*aq_subq;
	struct addrinfo		*aq_aifirst;
	struct addrinfo		*aq_ailast;
};

enum asr_state {
	ASR_STATE_INIT,
	ASR_STATE_NEXT_DOMAIN,
	ASR_STATE_QUERY_DOMAIN,
	ASR_STATE_NEXT_DB,
	ASR_STATE_QUERY_DB,
	ASR_STATE_NEXT_NS,
	ASR_STATE_QUERY_NS,
	ASR_STATE_READ_RR,
	ASR_STATE_QUERY_FILE,
	ASR_STATE_READ_FILE,
	ASR_STATE_SEND,
	ASR_STATE_RECV,
	ASR_STATE_NEXT_MATCH,
	ASR_STATE_TRY_MATCH,
	ASR_STATE_SUBQUERY,
	ASR_STATE_HALT,
};

int  asr_sockaddr_from_rr(struct sockaddr *, struct rr *);
int  asr_sockaddr_parse(struct sockaddr *, int, const char *);
void asr_sockaddr_set_port(struct sockaddr *, int);

/* config parsing */
int asr_parse_nameserver(struct sockaddr *, const char *);

int asr_parse_conf_file(struct asr *, const char *);
int asr_parse_conf_str(struct asr *, const char *);
int asr_parse_conf_cb(const char *,
		      int(*)(char **, int, void *, void *),
		      void *,
		      void *);

int   asr_add_searchdomain(struct asr *, const char *);
int   asr_db_add_nameserver(struct asr_db *, const char *);
void  asr_db_done(struct asr_db *);
char *asr_make_fqdn(const char *, const char *);

struct asr_query * asr_query_new(struct asr *, int);

void asr_query_free(struct asr_query *);

int asr_run_dns(struct asr_query *, struct asr_result *);
int asr_run_host(struct asr_query *, struct asr_result *);
int asr_run_addrinfo(struct asr_query *, struct asr_result *);

int asr_create_udp_socket(void);
int asr_prepare_dns_query(struct asr_query *);
int asr_send_dns_query(struct asr_query *);
int asr_recv_dns_response(struct asr_query *, struct asr_result *);

int pass0(char **, int,  void *, void *);
int pass1(char **, int,  void *, void *);
int ccount(const char *, char);
int asr_parse_line(FILE *, char **, int);
int asr_cmp_fqdn_name(const char *, char *);
int asr_is_fqdn(const char *);
int asr_get_port(const char *, const char *, int);
int asr_parse_hosts_cb(char **, int, void *, void *);
int asr_add_sockaddr(struct asr_query *, int, int, int, struct sockaddr *, int);


#ifdef ASR_DEBUG

void asr_dump(struct asr *);
void asr_dump_query(struct asr_query *);

int asr_debug = 0;

void
asr_dump(struct asr *a)
{
	char		 buf[256];
	int		 i, j;
	struct asr_db	*ad;

	printf("--------- ASR CONFIG ---------------\n");
	printf("DOMAIN \"%s\"\n", a->a_domain);
	printf("SEARCH\n");
	for(i = 0; i < a->a_domcount; i++)
		printf("   \"%s\"\n", a->a_dom[i]);
	printf("DB\n");
	for(ad = a->a_db, i = 0; i < a->a_dbcount; i++, ad++) {
		switch (ad->ad_type) {
		case ASR_DB_FILE:
			printf("   FILE \"%s\"\n", ad->ad_path);
			break;
		case ASR_DB_DNS:
			printf("   DNS timeout %ims, retries %i\n",
				ad->ad_timeout,
				ad->ad_retries);
			for(j = 0; j < ad->ad_count; j++)
				printf("     NS %s\n",
				    print_addr(ad->ad_sa[j], buf,
					sizeof buf));
			break;
		case ASR_DB_YP:
			printf("   YP\n");
			break;
		default:
			printf(" - ???? %i\n", ad->ad_type);
		}
	}
	printf("------------------------------------\n");
}

struct kv { int code; const char *name; };

const char *
kvlookup(struct kv *kv, int code)
{
	while (kv->name) {
		if (kv->code == code)
			return (kv->name);
		kv++;
	}
	return "???";
}

struct kv kv_query_type[] = {
	{ ASR_QUERY_DNS,		"ASR_QUERY_DNS"			},
	{ ASR_QUERY_HOST,		"ASR_QUERY_HOST"		},
	{ ASR_QUERY_ADDRINFO,		"ASR_QUERY_ADDRINFO"		},
	{ 0, NULL }
};

struct kv kv_db_type[] = {
	{ ASR_DB_FILE,			"ASR_DB_FILE"			},
	{ ASR_DB_DNS,			"ASR_DB_DNS"			},
	{ ASR_DB_YP,			"ASR_DB_YP"			},
	{ 0, NULL }
};

struct kv kv_state[] = {
	{ ASR_STATE_INIT,		"ASR_STATE_INIT"		},
	{ ASR_STATE_NEXT_DOMAIN,	"ASR_STATE_NEXT_DOMAIN"		},
	{ ASR_STATE_QUERY_DOMAIN,	"ASR_STATE_QUERY_DOMAIN"	},
	{ ASR_STATE_NEXT_DB,		"ASR_STATE_NEXT_DB"		},
	{ ASR_STATE_QUERY_DB,		"ASR_STATE_QUERY_DB"		},
	{ ASR_STATE_NEXT_NS,		"ASR_STATE_NEXT_NS"		},
	{ ASR_STATE_QUERY_NS,		"ASR_STATE_QUERY_NS"		},
	{ ASR_STATE_READ_RR,		"ASR_STATE_READ_RR"		},
	{ ASR_STATE_QUERY_FILE,		"ASR_STATE_QUERY_FILE"		},
	{ ASR_STATE_READ_FILE,		"ASR_STATE_READ_FILE"		},
	{ ASR_STATE_SEND,		"ASR_STATE_SEND"		},
	{ ASR_STATE_RECV,		"ASR_STATE_RECV"		},
	{ ASR_STATE_NEXT_MATCH,		"ASR_STATE_NEXT_MATCH"		},
	{ ASR_STATE_TRY_MATCH,		"ASR_STATE_TRY_MATCH"		},
	{ ASR_STATE_SUBQUERY,		"ASR_STATE_SUBQUERY"		},
	{ ASR_STATE_HALT,		"ASR_STATE_HALT"		},
	{ 0, NULL }
};

struct kv kv_transition[] = {
	{ ASR_NEED_READ,		"ASR_NEED_READ"			},
	{ ASR_NEED_WRITE,		"ASR_NEED_WRITE"		},
	{ ASR_YIELD,			"ASR_YIELD"			},
	{ ASR_DONE,			"ASR_DONE"			},
        { 0, NULL }
};

void
asr_dump_query(struct asr_query *aq)
{
	printf("%-25s dom %-2i db %-2i ns %-2i ns_cycles %-2i fd %-2i %ims",
		kvlookup(kv_state, aq->aq_state),
		aq->aq_dom_idx,
		aq->aq_db_idx,
		aq->aq_ns_idx,
		aq->aq_ns_cycles,
		aq->aq_fd,
		aq->aq_timeout);
	printf("\n");
}

#endif /* ASR_DEBUG */

int
asr_sockaddr_from_rr(struct sockaddr *sa, struct rr *rr)
{
	struct sockaddr_in	*in;
	struct sockaddr_in6	*in6;

	if (rr->rr_class != C_IN)
		return (-1);

	switch (rr->rr_type) {
	case T_A:
		in = (struct sockaddr_in*)sa;
		memset(in, 0, sizeof *in);
		in->sin_len = sizeof *in;
		in->sin_family = PF_INET;
		in->sin_addr = rr->rr.in_a.addr;
		in->sin_port = 0;
		return (0);
	case T_AAAA:
		in6 = (struct sockaddr_in6*)sa;
		memset(in6, 0, sizeof *in6);
		in6->sin6_len = sizeof *in6;
		in6->sin6_family = PF_INET6;
		in6->sin6_addr = rr->rr.in_aaaa.addr6;
		in6->sin6_port = 0;
		return (0);
	}

	return (-1);
}

int
asr_sockaddr_parse(struct sockaddr *sa, int family, const char *str)
{
	struct in_addr		 ina;
	struct in6_addr		 in6a;
	struct sockaddr_in	*in;
	struct sockaddr_in6	*in6;

	switch (family) {
	case PF_UNSPEC:
		if (asr_sockaddr_parse(sa, PF_INET, str) == 0)
			return (0);
		return asr_sockaddr_parse(sa, PF_INET6, str);

	case PF_INET:
		if (inet_pton(PF_INET, str, &ina) != 1)
			return (-1);

		in = (struct sockaddr_in *)sa;
		memset(in, 0, sizeof *in);
		in->sin_len = sizeof(struct sockaddr_in);
		in->sin_family = PF_INET;
		in->sin_addr.s_addr = ina.s_addr;
		return (0);

	case PF_INET6:
		if (inet_pton(PF_INET6, str, &in6a) != 1)
			return (-1);

		in6 = (struct sockaddr_in6 *)sa;
		memset(in6, 0, sizeof *in6);
		in6->sin6_len = sizeof(struct sockaddr_in6);
		in6->sin6_family = PF_INET6;
		in6->sin6_addr = in6a;
		return (0);
	}

	/* not reached */
	return (-1);
}

void
asr_sockaddr_set_port(struct sockaddr *sa, int portno)
{
	struct sockaddr_in	*in;
	struct sockaddr_in6	*in6;

	switch (sa->sa_family) {
	case PF_INET:
		in = (struct sockaddr_in *)sa;
		in->sin_port = portno;
		break;
	case PF_INET6:
		in6 = (struct sockaddr_in6 *)sa;
		in6->sin6_port = portno;
		break;
	}
}



int
asr_parse_nameserver(struct sockaddr *sa, const char *s)
{
	const char	*estr;
	char		 buf[256];
	char		*port = NULL;
	in_port_t	 portno = htons(53);

	if (*s == '[') {
		strlcpy(buf, s + 1, sizeof buf);
		s = buf;
		port = strchr(buf, ']');
		if (port == NULL)
			return (-1);
		*port++ = '\0';
		if (*port != ':')
			return (-1);
		port++;
	}
	
	if (port) {
		portno = htons(strtonum(port, 1, USHRT_MAX, &estr));
		if (estr)
			return (-1);
	}

	if (asr_sockaddr_parse(sa, PF_UNSPEC, s) == -1)
		return (-1);

	asr_sockaddr_set_port(sa, portno);

	return (0);
}


int
asr_db_add_nameserver(struct asr_db *ad, const char *nameserver)
{
	struct sockaddr_storage	ss;

	if (ad->ad_type != ASR_DB_DNS)
		return (-1);

	if (ad->ad_count == ASR_MAXNS)
		return (-1);

	if (asr_parse_nameserver((struct sockaddr*)&ss, nameserver))
		return (-1);

	if ((ad->ad_sa[ad->ad_count] = calloc(1, ss.ss_len)) == NULL)
		return (0);

	memmove(ad->ad_sa[ad->ad_count], &ss, ss.ss_len);
	ad->ad_count += 1;

	return (1);
}

int
asr_add_searchdomain(struct asr *asr, const char *domain)
{
	if (asr->a_domcount == ASR_MAXDOM)
		return (-1);

	if ((asr->a_dom[asr->a_domcount] = asr_make_fqdn(domain, NULL)) == NULL)
		return (0);

	asr->a_domcount += 1;

	return (1);
}


int
pass0(char **tok, int n,  void *a0, void *a1)
{
	struct asr	*asr = (struct asr*)a0;
	struct asr_db	*ad;
	int		*nscount = (int*)a1;
	int		 i, j;

	/* search for lookup, domain, and count nameservers */

	if (!strcmp(tok[0], "nameserver")) {
		*nscount += 1;

	} else if (!strcmp(tok[0], "domain")) {

		if (n != 2)
			return (0);

		if (asr->a_domain)
			return (0);

		asr->a_domain = strdup(tok[1]);

	} else if (!strcmp(tok[0], "lookup")) {

		/* ignore the line if we already set lookup */
		if (asr->a_dbcount != 0)
			return (0);

		if (n - 1 > ASR_MAXDB)
			return (0);

		/* ensure that each lookup is only given once */
		for(i = 1; i < n; i++)
			for(j = i + 1; j < n; j++)
				if (!strcmp(tok[i], tok[j]))
					return (0);

		for(i = 1, ad = asr->a_db; i < n;
		    i++, asr->a_dbcount++, ad++) {

			if (!strcmp(tok[i], "yp")) {
				ad->ad_type = ASR_DB_YP;

			} else if (!strcmp(tok[i], "bind")) {
				ad->ad_type = ASR_DB_DNS;
				ad->ad_count = 0;
				ad->ad_timeout = 1000;
				ad->ad_retries = 3;

			} else if (!strcmp(tok[i], "file")) {

				ad->ad_type = ASR_DB_FILE;
				ad->ad_path = strdup(DEFAULT_HOSTFILE);

			} else {
				/* ignore the line */
				asr->a_dbcount = 0;
				return (0);
			}
		}
	} else if (!strcmp(tok[0], "search")) {
		/* resolv.conf says the last line wins */
		for(i = 0; i < asr->a_domcount; i++)
			free(asr->a_dom[i]);
		asr->a_domcount = 0;
		for(i = 1; i < n; i++)
			asr_add_searchdomain(asr, tok[i]);
	}

	return (0);
}

int
pass1(char **tok, int n,  void *a0, void *a1)
{
	struct asr_db *ad = (struct asr_db*) a0;

	/* fill the DNS db with the specified nameservers */

	if (!strcmp(tok[0], "nameserver")) {
		if (n != 2)
			return (0);
		asr_db_add_nameserver(ad, tok[1]);
	}
	return (0);
}

int
asr_parse_conf_cb(const char	 *conf,
		  int		(*cb)(char**, int, void*, void*),
		  void		 *arg0,
		  void		 *arg1)
{
	size_t		 len;
	const char	*line;
	char		 buf[1024];
	char		*tok[10], **tp, *cp;
	int		 ntok;

	line = conf;
	while (*line) {
		len = strcspn(line, "\n\0");
		if (len < sizeof buf) {
			memmove(buf, line, len);
			buf[len] = '\0';
		} else
			buf[0] = '\0';
		line += len;
		if (*line == '\n')
			line++;
		buf[strcspn(buf, ";#")] = '\0';
		for(cp = buf, tp = tok, ntok = 0;
		    tp < &tok[10] && (*tp = strsep(&cp, " \t")) != NULL;)
			if (**tp != '\0') {
				tp++;
				ntok++;
			}
		*tp = NULL;

		if (tok[0] == NULL)
			continue;

		if (cb(tok, ntok, arg0, arg1))
			break;
	}

	return (0);
}

int
ccount(const char *s, char c)
{
	int	n = 0;

	while(*s)
		if (*s++ == c)
			n += 1;

	return (n);
}

int
asr_parse_conf_str(struct asr *asr, const char *conf)
{
	char		 buf[512], *ch;
	struct asr_db	*ad;
	int		 i;
	int		 nscount = 0;


	asr_parse_conf_cb(conf, pass0, asr, &nscount);

	if (asr->a_dbcount == 0) {
		/* no lookup directive */
		asr_parse_conf_cb(DEFAULT_LOOKUP, pass0, asr, &nscount);
	}

	ad = NULL;
	for(i = 0; i < asr->a_dbcount; i++)
		if (asr->a_db[i].ad_type == ASR_DB_DNS) {
			ad = &asr->a_db[i];
			break;
		}

	if (nscount && ad)
		asr_parse_conf_cb(conf, pass1, ad, NULL);

	if (asr->a_domain == NULL)
		if (gethostname(buf, sizeof buf) == 0) {
			ch = strchr(buf, '.');
			if (ch)
				asr->a_domain = strdup(ch + 1);
			else /* assume root see resolv.conf(5) */
				asr->a_domain = strdup("");
		}

	if (asr->a_domcount == 0)
		for(ch = asr->a_domain; ch; ) {
			asr_add_searchdomain(asr, ch);
			ch = strchr(ch, '.');
			if (ch && ccount(++ch, '.') == 0)
				break;
		}

	return (0);
}

int
asr_parse_conf_file(struct asr *a, const char * path)
{
	FILE	*cf;
	char	 buf[1024];
	ssize_t	 r;

	cf = fopen(path, "r");
	if (cf == NULL)
		return (-1);

	/* XXX make sure we read the whole file */
	r = fread(buf, 1, sizeof buf - 1, cf);
	fclose(cf);
	if (r == -1)
		return (-1);
	buf[r] = '\0';
 
	return asr_parse_conf_str(a, buf);
}

/**********************
 * namedb parser
 **********************/

int
asr_parse_line(FILE		 *file,
	       char		**tokens,
	       int		  ntoken)
{
	size_t	  len;
	char	 *buf, *cp, **tp;
	int	  ntok;

  again:
	if ((buf = fgetln(file, &len)) == NULL)
		return (-1);

	if (buf[len - 1] == '\n')
		len--;

	buf[len] = '\0';
	buf[strcspn(buf, "#")] = '\0';
	for(cp = buf, tp = tokens, ntok = 0;
	    ntok < ntoken && (*tp = strsep(&cp, " \t")) != NULL;)
		if (**tp != '\0') {
			tp++;
			ntok++;
		}
	*tp = NULL;
	if (tokens[0] == NULL)
		goto again;

	return (ntok);
}

struct asr *
asr_resolver(const char *conf)
{
	int		 r;
	struct asr	*asr;

#ifdef ASR_DEBUG
	if (asr_debug == 0)
		if(getenv("ASR_DEBUG")) {
		printf("asr: %zu\n", sizeof(struct asr));
		printf("asr_db: %zu\n", sizeof(struct asr_db));
		printf("asr_query: %zu\n", sizeof(struct asr_query));
		printf("asr_result: %zu\n", sizeof(struct asr_result));
		asr_debug = 1;
	}
#endif
	if ((asr = calloc(1, sizeof(*asr))) == NULL)
		return (NULL);

	asr->a_refcount = 1;
	asr->a_ndots = 1;

	if (conf == NULL) {
		r = asr_parse_conf_file(asr, DEFAULT_CONFFILE);
		if (r == -1)
			r = asr_parse_conf_str(asr, DEFAULT_CONF);
	} else {
		r = asr_parse_conf_str(asr, conf);
	}
	if (r == -1) {
		free(asr);
		return (NULL);
	}

#ifdef ASR_DEBUG
	if (asr_debug)
		asr_dump(asr);
#endif

	return (asr);
}

struct asr_query *
asr_query_new(struct asr *asr, int type)
{
	struct asr_query	*aq;

	if ((aq = calloc(1, sizeof(*aq))) == NULL)
		return (NULL);

	aq->aq_asr = asr;
	aq->aq_fd = -1;
	aq->aq_type = type;
	asr->a_refcount += 1;

	aq->aq_state = ASR_STATE_INIT;

	return (aq);
}

void
asr_db_done(struct asr_db *ad)
{
	int	i;

	switch(ad->ad_type) {
	case ASR_DB_DNS:
		for(i = 0; i < ad->ad_count; i++)
			free(ad->ad_sa[i]);
		break;

	case ASR_DB_YP:
		break;

	case ASR_DB_FILE:
		free(ad->ad_path);
		break;
	default:
		errx(1, "asr_db_done: unknown db type");
	}
}

void
asr_done(struct asr *asr)
{
	int	i;

	asr->a_refcount--;

	if (asr->a_refcount == 0) {
		if (asr->a_domain)
			free(asr->a_domain);

		for(i = 0; i < asr->a_dbcount; i++)
			asr_db_done(&asr->a_db[i]);

		for(i = 0; i < asr->a_domcount; i++)
			free(asr->a_dom[i]);

		free(asr);
	}
}

int
asr_cmp_fqdn_name(const char *fqdn, char *name)
{
	int i;

	/* compare a fqdn with a name that my not end with a dot */

	for (i = 0; fqdn[i] && name[i]; i++)
		if (fqdn[i] != name[i])
			return (-1);

	if (fqdn[i] == name[i])
		return (0);

	if (fqdn[i] == 0 || fqdn[i] != '.' || fqdn[i+1] != 0)
		return (-1);

	return (0);
}


int
asr_is_fqdn(const char *name)
{
	size_t	len;

	len = strlen(name);
	return (len > 0 && name[len -1] == '.');
}

char *
asr_make_fqdn(const char *name, const char *domain)
{
	char	*fqdn;
	size_t	 len;

	if (domain == NULL)
		domain = ".";
#ifdef ASR_DEBUG
	else
		if (!asr_is_fqdn(domain))
			errx(1, "domain is not FQDN: %s", domain);
#endif

	len = strlen(name);
	if (len == 0) {
		fqdn = strdup(domain);
	} else if (name[len - 1] !=  '.') {
		if (domain[0] == '.')
			domain += 1;
		len += strlen(domain) + 2;
		fqdn = malloc(len);
		if (fqdn == NULL)
			return (NULL);
		strlcpy(fqdn, name, len);
		strlcat(fqdn, ".", len);
		strlcat(fqdn, domain, len);
	} else {
		fqdn = strdup(name);
	}

	return (fqdn);
}

int
asr_prepare_dns_query(struct asr_query *aq)
{
	struct packed		 p;
	struct header		 h;

	if (dname_from_fqdn(aq->aq_fqdn,
		aq->aq_query.q_dname,
		sizeof(aq->aq_query.q_dname)) == -1)
		return (-1);

        aq->aq_reqid = arc4random();

	memset(&h, 0, sizeof h);
	h.id = aq->aq_reqid;
	if (!(aq->aq_flags & ASR_NOREC))
		h.flags |= RD_MASK;
	h.qdcount = 1;

	packed_init(&p, aq->aq_opkt, sizeof(aq->aq_opkt));
	pack_header(&p, &h);
	pack_query(&p, aq->aq_query.q_type, aq->aq_query.q_class,
		aq->aq_query.q_dname);
	aq->aq_opktlen = p.offset;

	return (0);
}

struct asr_query *
asr_query_dns(struct asr	*asr,
	      uint16_t		 type,
	      uint16_t		 class,
	      const char	*name,
	      int		 flags)
{
	struct asr_query	*aq;

	if ((aq = asr_query_new(asr, ASR_QUERY_DNS)) == NULL)
		return (NULL);

	aq->aq_flags = flags;
	aq->aq_query.q_type = type;
	aq->aq_query.q_class = class;
	aq->aq_fqdn = asr_make_fqdn(name, NULL);
	if (aq->aq_fqdn == NULL)
		goto abort;

	return (aq);

abort:
	asr_query_free(aq);

	return (NULL);
}


struct asr_query *
asr_query_addrinfo(struct asr			*asr,
		   const char			*hostname,
		   const char			*servname,
		   const struct addrinfo	*hints)
{
	struct asr_query	*aq;

	if ((aq = asr_query_new(asr, ASR_QUERY_ADDRINFO)) == NULL)
		return (NULL);

	if (hostname && (aq->aq_hostname = strdup(hostname)) == NULL)
		goto abort;
	if (servname && (aq->aq_servname = strdup(servname)) == NULL)
		goto abort;
	if (hints)
		memmove(&aq->aq_hints, hints, sizeof *hints);
	else {
		memset(&aq->aq_hints, 0, sizeof aq->aq_hints);
		aq->aq_hints.ai_family = PF_UNSPEC;
	}

	return (aq);

abort:
	asr_query_free(aq);
	return (NULL);
}

int
asr_parse_hosts_cb(char **tok, int n,  void *a0, void *a1)
{
	struct asr_query	*aq = (struct asr_query*) a0;
	struct asr_result	*ar = (struct asr_result*) a1;
	int	i;

	for (i = 1; i < n; i++) {
		if (strcmp(tok[i], aq->aq_host))
			continue;
		if (asr_sockaddr_parse(&ar->ar_sa.any, aq->aq_family, tok[0]) == -1)
			continue;
		ar->ar_cname = strdup(tok[1]);
		return (1);
	}

	return (0);
}

struct asr_query *
asr_query_host(struct asr *asr,
	       const char *host,
	       int	   family)
{
	struct asr_query	*aq;

	if ((aq = asr_query_new(asr, ASR_QUERY_HOST)) == NULL)
		return (NULL);

	aq->aq_host = strdup(host);

	if (aq->aq_host == NULL)
		goto abort;

	aq->aq_family = family;

	return (aq);

abort:
	asr_query_free(aq);
	return (NULL);
}


void
asr_abort(struct asr_query *aq)
{
	asr_query_free(aq);
}


int
asr_run(struct asr_query *aq, struct asr_result *ar)
{
	int	r;

#ifdef ASR_DEBUG
	if (asr_debug) {
		printf("-> QUERY %p(%p) %s\n",
			aq, aq->aq_asr,
			kvlookup(kv_query_type, aq->aq_type));
	}
#endif

	switch(aq->aq_type) {
	case ASR_QUERY_DNS:
		r = asr_run_dns(aq, ar);
		break;
	case ASR_QUERY_HOST:
		r = asr_run_host(aq, ar);
		break;
	case ASR_QUERY_ADDRINFO:
		r = asr_run_addrinfo(aq, ar);
		break;
	default:
		ar->ar_err = EOPNOTSUPP;
		ar->ar_errstr = "unknown query type";
		r = ASR_DONE;
	}
#ifdef ASR_DEBUG
	if (asr_debug) {
		printf("<- ");
		asr_dump_query(aq);
		printf("   = %s\n", kvlookup(kv_transition, r));
	}
#endif
	if (r == ASR_DONE)
		asr_query_free(aq);

	return (r);
}

int
asr_run_sync(struct asr_query *aq, struct asr_result *ar)
{
	struct pollfd		 fds[1];
	int			 r;

	for(;;) {
		r = asr_run(aq, ar);
		if (r == ASR_DONE || r == ASR_YIELD)
			break;
		fds[0].fd = ar->ar_fd;
		fds[0].events = (r == ASR_NEED_READ) ? POLLIN : POLLOUT;
	again:
		r = poll(fds, 1, ar->ar_timeout);
		if (r == -1 && errno == EINTR)
			goto again;
		if (r == -1) /* impossible? */
			err(1, "poll");
	}

	return r;
}

int
asr_create_udp_socket(void)
{
	int	sockfd;
	int	flags;

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		err(1, "socket");

	if ((flags = fcntl(sockfd, F_GETFL, 0)) == -1)
		err(1, "fcntl F_GETFL");

	flags |= O_NONBLOCK;

	if ((flags = fcntl(sockfd, F_SETFL, flags)) == -1)
		err(1, "fcntl F_SETFL");

	return (sockfd);
}

int
asr_send_dns_query(struct asr_query *aq)
{
	struct asr_db	*ad;
	struct sockaddr	*sa;
	ssize_t		 e;

	ad = &aq->aq_asr->a_db[aq->aq_db_idx];
	sa = ad->ad_sa[aq->aq_ns_idx];

	if (aq->aq_fd == -1)
		aq->aq_fd = asr_create_udp_socket();
	aq->aq_timeout = ad->ad_timeout;

	for(;;) {
		e = sendto(aq->aq_fd, aq->aq_opkt, aq->aq_opktlen, 0, sa, sa->sa_len);
		if (e == -1) {
			if (errno != EINTR)
				return (e);
			continue;
		}
		break;
	}

	return (0);
}

int
asr_recv_dns_response(struct asr_query *aq, struct asr_result *ar)
{
	struct packed	p;
	struct header	h;
	struct query	q;
	struct rr	rr;
	char		buf[PACKET_MAXLEN];
	int		r;
	struct sockaddr	*sa;
	socklen_t	 sl;
	ssize_t		 len;

	sa = &ar->ar_sa.any;

    retry:
	sl = sizeof(ar->ar_sa);
	len = recvfrom(aq->aq_fd, buf, sizeof buf, 0, sa, &sl);
	if (len == -1) {
		if (errno == EINTR)
			goto retry;
		if (errno == EAGAIN)
			return (-2);
		return (-1);
	}

	packed_init(&p, buf, len);

	/* NOTE: We are very strict about what we accept as a valid dns response,
	 * to make sure we don't throw stupid things back to the upper layers.
	 * Though, we might want to be a more lenient in some cases, so we
	 * want to be able to tweak the behaviour through the query flags:
	 *      - ignore non-critical problems in header flags
	 *	- accept truncated packet, as long as the answer is complete
	 */

	unpack_header(&p, &h);
	if (p.err)
		return (-1);
	if (h.id != aq->aq_reqid)
		return (-1);
	if (h.qdcount != 1)
		return (-1);
	if ((h.flags & Z_MASK) != 0)
		return (-1);	/* should be zero, we could allow this */
	if (h.flags & TC_MASK)
		return (-1);	/* truncated. we could allow this */
	if (OPCODE(h.flags) != OP_QUERY)
		return (-1);	/* actually, it depends on the request */
	if ((h.flags & QR_MASK) == 0)
		return (-1);	/* not a response */

	unpack_query(&p, &q);
	if (p.err)
		return (-1);
	if (q.q_type != aq->aq_query.q_type ||
	    q.q_class != aq->aq_query.q_class ||
	    strcasecmp(q.q_dname, aq->aq_query.q_dname))
		return (-1);

	/* validate the rest of the packet */
	for(r = h.ancount + h.nscount + h.arcount; r; r--)
		unpack_rr(&p, &rr);

	if (p.err || (p.offset != (size_t)len))
		return (-1);

	/* return the data */
	ar->ar_datalen = len;
	ar->ar_data = calloc(1, len);
	/* XXX report to the user */
	if (ar->ar_data == NULL)
		return (-1);

	memmove(ar->ar_data, buf, len);

	return (0);
}

void
asr_query_free(struct asr_query *aq)
{
	struct asr_acache	*a;

	while ((a = aq->aq_addrcache)) {
		aq->aq_addrcache = a->aa_next;
		free(a);
	}

	if (aq->aq_aifirst)
		freeaddrinfo(aq->aq_aifirst);
	if (aq->aq_subq)
		asr_abort(aq->aq_subq);
	if (aq->aq_host)
		free(aq->aq_host);
	if (aq->aq_fqdn)
		free(aq->aq_fqdn);
	if (aq->aq_pktin)
		free(aq->aq_pktin);
	if (aq->aq_hostname)
		free(aq->aq_hostname);
	if (aq->aq_servname)
		free(aq->aq_servname);
	if (aq->aq_fd != -1) {
		close(aq->aq_fd);
		aq->aq_fd = -1;
	}
	asr_done(aq->aq_asr);
	free(aq);
}


int
asr_run_dns(struct asr_query *aq, struct asr_result *ar)
{
	struct asr_db	*ad;

	for(;;) { /* block not indented on purpose */
#ifdef ASR_DEBUG
	if (asr_debug) {
		printf("   ");
		asr_dump_query(aq);
	}
#endif
	switch(aq->aq_state) {

	case ASR_STATE_INIT:
		if (asr_prepare_dns_query(aq) == -1) {
			ar->ar_err = EINVAL;
			aq->aq_state = ASR_STATE_HALT;
			break;
		}
		aq->aq_ns_cycles = -1;
		aq->aq_db_idx = 0;
		aq->aq_state = ASR_STATE_QUERY_DB;
		break;

	case ASR_STATE_NEXT_DB:
		aq->aq_db_idx += 1;
		aq->aq_state = ASR_STATE_QUERY_DB;
		break;

	case ASR_STATE_QUERY_DB:
		if (aq->aq_db_idx >= aq->aq_asr->a_dbcount) {
			ar->ar_err = (aq->aq_ns_cycles == -1) ? 
				ENODEV : ETIMEDOUT;
			aq->aq_state = ASR_STATE_HALT;
			break;
		}

		ad = &aq->aq_asr->a_db[aq->aq_db_idx];
		if (ad->ad_type != ASR_DB_DNS) {
			aq->aq_state = ASR_STATE_NEXT_DB;
			break;
		}
		aq->aq_ns_cycles = 0;
		aq->aq_ns_idx = 0;
		aq->aq_state = ASR_STATE_QUERY_NS;
		break;

	case ASR_STATE_NEXT_NS:
		ad = &aq->aq_asr->a_db[aq->aq_db_idx];
		aq->aq_ns_idx += 1;
		if (aq->aq_ns_idx >= ad->ad_count) {
			aq->aq_ns_idx = 0;
			aq->aq_ns_cycles++;
		}
		if (aq->aq_ns_cycles >= ad->ad_retries) {
			aq->aq_state = ASR_STATE_NEXT_DB;
			break;
		}
		aq->aq_state = ASR_STATE_QUERY_NS;
		break;

	case ASR_STATE_QUERY_NS:
		ad = &aq->aq_asr->a_db[aq->aq_db_idx];
		if (aq->aq_ns_idx >= ad->ad_count) {
			aq->aq_state = ASR_STATE_NEXT_NS;
			break;
		}
		aq->aq_state = ASR_STATE_SEND;
		break;

	case ASR_STATE_SEND:
		if (asr_send_dns_query(aq) == 0) {
			aq->aq_state = ASR_STATE_RECV;
			ar->ar_fd = aq->aq_fd;
			ar->ar_timeout = aq->aq_timeout;
			return (ASR_NEED_READ);
		}
		aq->aq_state = ASR_STATE_NEXT_NS;
		break;

	case ASR_STATE_RECV:
		switch (asr_recv_dns_response(aq, ar)) {
		case -2: /* timeout */
			aq->aq_state = ASR_STATE_NEXT_NS;
			break;
		case -1: /* fail */
			aq->aq_state = ASR_STATE_NEXT_NS;
			break;
		default:
			ar->ar_err = 0;
			aq->aq_state = ASR_STATE_HALT;
			break;
		}
		break;

	case ASR_STATE_HALT:
		switch(ar->ar_err) {
		case 0:
			ar->ar_errstr = NULL;
			break;
		case ENOMEM:
			ar->ar_errstr = "out if memory";
			break;
		case EINVAL:
			ar->ar_errstr = "invalid address family";
			break;
		case ENODEV:
			ar->ar_errstr = "no nameserver specified";
			break;
		case ETIMEDOUT:
			ar->ar_errstr = "nameservers timeout";
			break;
		default:
			ar->ar_errstr = "unknown error";
		}
		return (ASR_DONE);

	default:
		errx(1, "asr_run_dns: unknown state");
	}}
}


int
asr_run_host(struct asr_query *aq, struct asr_result *ar)
{
	struct header	 h;
	struct query	 q;
	struct rr	 rr;
	struct asr_db	*ad;
	char		*tok[10];
	int		 ntok = 10, i, n;

	for(;;) { /* block not indented on purpose */
#ifdef ASR_DEBUG
	if (asr_debug) {
		printf("   ");
		asr_dump_query(aq);
	}
#endif
	switch(aq->aq_state) {

	case ASR_STATE_INIT:
		if (aq->aq_family != AF_INET &&
		    aq->aq_family != AF_INET6) {
			ar->ar_err = EINVAL;
			aq->aq_state = ASR_STATE_HALT;
			break;
		}
		aq->aq_count = 0;
		aq->aq_dom_idx = 0;
		/* check if we need to try it as an absolute name first */
		if (ccount(aq->aq_host, '.') >= aq->aq_asr->a_ndots)
			aq->aq_dom_idx = -1;
		aq->aq_state = ASR_STATE_QUERY_DOMAIN;
		break;

	case ASR_STATE_NEXT_DOMAIN:
		/* no domain search for fully qualified names */
		if (asr_is_fqdn(aq->aq_host)) {
			ar->ar_err = ENOENT;
			aq->aq_state = ASR_STATE_HALT;
			break;
		}
		aq->aq_dom_idx += 1;
		aq->aq_state = ASR_STATE_QUERY_DOMAIN;
		break;

	case ASR_STATE_QUERY_DOMAIN:
		if (aq->aq_dom_idx >= aq->aq_asr->a_domcount) {
			ar->ar_err = ENOENT;
			aq->aq_state = ASR_STATE_HALT;
			break;
		}
		if (aq->aq_fqdn)
			free(aq->aq_fqdn);

		if (aq->aq_dom_idx == -1) /* try as absolute first */
			aq->aq_fqdn = asr_make_fqdn(aq->aq_host, NULL);
		else
			aq->aq_fqdn = asr_make_fqdn(aq->aq_host,
			    aq->aq_asr->a_dom[aq->aq_dom_idx]);

		if (aq->aq_fqdn == NULL) {
			ar->ar_err = ENOMEM;
			aq->aq_state = ASR_STATE_HALT;
			break;
		}
		aq->aq_db_idx = 0;
		aq->aq_state = ASR_STATE_QUERY_DB;
		break;

	case ASR_STATE_NEXT_DB:
		aq->aq_db_idx += 1;
		aq->aq_state = ASR_STATE_QUERY_DB;
		break;

	case ASR_STATE_QUERY_DB:
		if (aq->aq_db_idx >= aq->aq_asr->a_dbcount) {
			aq->aq_state = ASR_STATE_NEXT_DOMAIN;
			break;
		}

		ad = &aq->aq_asr->a_db[aq->aq_db_idx];
		switch(ad->ad_type) {
		case ASR_DB_DNS:
			if (aq->aq_family == AF_INET)
				aq->aq_query.q_type = T_A;
			else /* AF_INET6 */
				aq->aq_query.q_type = T_AAAA;
			aq->aq_query.q_class = C_IN;
			aq->aq_flags = 0;
			asr_prepare_dns_query(aq); /* can't fail */
			aq->aq_ns_cycles = 0;
			aq->aq_ns_idx = 0;
			aq->aq_state = ASR_STATE_QUERY_NS;
			break;
		case ASR_DB_FILE:
			aq->aq_state = ASR_STATE_QUERY_FILE;
			break;
		default:
			aq->aq_state = ASR_STATE_NEXT_DB;
		}
		break;

	case ASR_STATE_NEXT_NS:
		ad = &aq->aq_asr->a_db[aq->aq_db_idx];
		aq->aq_ns_idx += 1;
		if (aq->aq_ns_idx >= ad->ad_count) {
			aq->aq_ns_idx = 0;
			aq->aq_ns_cycles++;
		}
		if (aq->aq_ns_cycles >= ad->ad_retries) {
			aq->aq_state = ASR_STATE_NEXT_DB;
			break;
		}
		aq->aq_state = ASR_STATE_QUERY_NS;
		break;

	case ASR_STATE_QUERY_NS:
		ad = &aq->aq_asr->a_db[aq->aq_db_idx];
		if (aq->aq_ns_idx >= ad->ad_count) {
			aq->aq_state = ASR_STATE_NEXT_NS;
			break;
		}
		aq->aq_state = ASR_STATE_SEND;
		break;

	case ASR_STATE_SEND:
		if (asr_send_dns_query(aq) == 0) {
			aq->aq_state = ASR_STATE_RECV;
			ar->ar_fd = aq->aq_fd;
			ar->ar_timeout = aq->aq_timeout;
			return (ASR_NEED_READ);
		}
		aq->aq_state = ASR_STATE_NEXT_NS;
		break;

	case ASR_STATE_RECV:
		switch (asr_recv_dns_response(aq, ar)) {
		case -2: /* timeout */
		case -1: /* fail */
			aq->aq_state = ASR_STATE_NEXT_NS;
			break;
		default:
			aq->aq_pktin = ar->ar_data;
			aq->aq_pktlen = ar->ar_datalen;
			packed_init(&aq->aq_packed, aq->aq_pktin, aq->aq_pktlen);
			unpack_header(&aq->aq_packed, &h);
			aq->aq_nanswer = h.ancount;
			for(; h.qdcount; h.qdcount--)
				unpack_query(&aq->aq_packed, &q);
			aq->aq_state = ASR_STATE_READ_RR;
			break;
		}
		break;

	case ASR_STATE_READ_RR:
		if (aq->aq_nanswer == 0) {
			free(aq->aq_pktin);
			aq->aq_pktin = NULL;
			if (aq->aq_count) {
				ar->ar_err = 0;
				aq->aq_state = ASR_STATE_HALT;
			} else
				aq->aq_state = ASR_STATE_NEXT_NS;
			break;
		}
		aq->aq_nanswer -= 1;
		unpack_rr(&aq->aq_packed, &rr);
		if (rr.rr_type == aq->aq_query.q_type &&
		    rr.rr_class == aq->aq_query.q_class) {
			aq->aq_count += 1;
			ar->ar_count = aq->aq_count;
			asr_sockaddr_from_rr(&ar->ar_sa.any, &rr);
			ar->ar_cname = NULL; /* XXX */
			return (ASR_YIELD);
		}
		break;

	case ASR_STATE_QUERY_FILE:
		ad = &aq->aq_asr->a_db[aq->aq_db_idx];
		aq->aq_file = fopen(ad->ad_path, "r");
		if (aq->aq_file == NULL)
			aq->aq_state = ASR_STATE_NEXT_DB;
		else
			aq->aq_state = ASR_STATE_READ_FILE;
		break;

	case ASR_STATE_READ_FILE:
		n = asr_parse_line(aq->aq_file, tok, ntok);
		if (n == -1) {
			fclose(aq->aq_file);
			aq->aq_file = NULL;
			if (aq->aq_count) {
				ar->ar_err = 0;
				aq->aq_state = ASR_STATE_HALT;
			} else
				aq->aq_state = ASR_STATE_NEXT_DB;
			break;
		}

		for (i = 1; i < n; i++) {
			/* for the first round, try the host as-is  */
			/* XXX not nice */
			if (aq->aq_dom_idx <= 0 && !strcmp(aq->aq_host, tok[i])) {
			} else if (asr_cmp_fqdn_name(aq->aq_fqdn, tok[i]) == -1)
				continue;
			if (asr_sockaddr_parse(&ar->ar_sa.any, aq->aq_family, tok[0]) == -1)
				continue;

			aq->aq_count += 1;
			ar->ar_count = aq->aq_count;
			ar->ar_cname = strdup(tok[1]);
			return (ASR_YIELD);
		}
		break;

	case ASR_STATE_HALT:
		ar->ar_count = aq->aq_count;
		switch(ar->ar_err) {
		case 0:
			ar->ar_errstr = NULL;
			break;
		case ENOMEM:
			ar->ar_errstr = "out if memory";
			break;
		case ENOENT:
			ar->ar_errstr = "not found";
			break;
		case EINVAL:
			ar->ar_errstr = "invalid address family";
			break;
		default:
			ar->ar_errstr = "unknown error";
		}

		return (ASR_DONE);

	default:
		errx(1, "asr_run_dns: unknown state");
	}}
}

int
asr_get_port(const char *servname,
	     const char *proto,
	     int numonly)
{
	struct servent		se;
	struct servent_data	sed;
	int			port, r;
	const char*		e;

	if (servname == NULL)
		return (0);

	e = NULL;
	port = strtonum(servname, 0, USHRT_MAX, &e);
	if (e == NULL)
		return htons(port);
	if (errno == ERANGE)
		return (-1);
	if (numonly)
		return (-1);

	memset(&sed, 0, sizeof(sed));
	r = getservbyname_r(servname, proto, &se, &sed);
	port = se.s_port;
	endservent_r(&sed);

	if (r == -1)
		return (-1);

	return (port);
}

int
asr_add_sockaddr(struct asr_query *aq,
	int family,
	int socktype,
	int protocol,
	struct sockaddr	*sa,
	int cache)
{
	struct asr_acache	*a;
	struct addrinfo		*ai;
	struct sockaddr_in	*in;
	struct sockaddr_in6	*in6;
	const char		*proto;
	int			 port;

	switch (protocol) {
		case IPPROTO_TCP:
			proto = "tcp";
			break;
		case IPPROTO_UDP:
			proto = "udp";
			break;
		default:
			proto = NULL;
	}

	port = -1;
	if (proto) {
		port = asr_get_port(aq->aq_servname, proto,
				    aq->aq_flags & AI_NUMERICSERV);
		if (port == -1)
			return (-1);
	}

	ai = calloc(1, sizeof *ai + sa->sa_len);
	if (ai == NULL)
		return (-1);
	ai->ai_family = family;
	ai->ai_socktype = socktype;
	ai->ai_protocol = protocol;
	ai->ai_addrlen = sa->sa_len;
	ai->ai_addr = (void*)(ai+1);
	memmove(ai->ai_addr, sa, sa->sa_len);

	if (port != -1) {
		switch(family) {
		case PF_INET:
			in = (struct sockaddr_in*)ai->ai_addr;
			in->sin_port = port;
			break;
		case PF_INET6:
			in6 = (struct sockaddr_in6*)ai->ai_addr;
			in6->sin6_port = port;
			break;
		}
	}

	if (aq->aq_aifirst == NULL)
		aq->aq_aifirst = ai;
	if (aq->aq_ailast)
		aq->aq_ailast->ai_next = ai;
	aq->aq_ailast = ai;

	aq->aq_count += 1;

	if (!cache)
		return (0);

	a = calloc(1, sizeof *a);
	if (a == NULL)
		return (0); /* XXX is this actually a failure ? */

	memmove(&a->aa_sa.any, sa, sa->sa_len);

	if (aq->aq_addrcache == NULL)
		aq->aq_addrcache = a;
	if (aq->aq_addrcachelast)
		aq->aq_addrcachelast->aa_next = a;
	aq->aq_addrcachelast = a;

	return (0);
}

struct match {
	int family;
	int socktype;
	int protocol;
};

static const struct match matches[] = {
	{ PF_INET,	SOCK_DGRAM,	IPPROTO_UDP	},
	{ PF_INET,	SOCK_STREAM,	IPPROTO_TCP	},
	{ PF_INET,	SOCK_RAW,	0		},
	{ PF_INET6,	SOCK_DGRAM,	IPPROTO_UDP	},
	{ PF_INET6,	SOCK_STREAM,	IPPROTO_TCP	},
	{ PF_INET6,	SOCK_RAW,	0		},
	{ -1, 		0, 		0, 		},
};

static const int families[] = { PF_INET, PF_INET6, -1 };

#define MATCH_FAMILY(a, b) ((a) == matches[(b)].family || (a) == PF_UNSPEC)
/* do not match SOCK_RAW unless explicitely specified */
#define MATCH_SOCKTYPE(a, b) ((a) == matches[(b)].socktype || ((a) == 0 && matches[(b)].socktype != SOCK_RAW))
#define MATCH_PROTO(a, b) ((a) == matches[(b)].protocol || (a) == 0)

int
asr_run_addrinfo(struct asr_query *aq, struct asr_result *ar)
{
	struct asr_acache *ac, aa;
	const char	  *str;
	struct addrinfo	  *ai;
	int		   i, family, r, stop;

	for(;;) { /* block not indented on purpose */
#ifdef ASR_DEBUG
	if (asr_debug) {
		printf("   ");
		asr_dump_query(aq);
	}
#endif
	switch(aq->aq_state) {

	case ASR_STATE_INIT:
		aq->aq_count = 0;
		aq->aq_state = ASR_STATE_HALT;

		if (aq->aq_hostname == NULL &&
		    aq->aq_servname == NULL) {
			ar->ar_err = EAI_BADHINTS;
			break;
		}

		ai = &aq->aq_hints;

		if (ai->ai_addrlen ||
		    ai->ai_canonname ||
		    ai->ai_addr ||
		    ai->ai_next) {
			ar->ar_err = EAI_BADHINTS;
			break;
		}

		if (ai->ai_flags & ~AI_MASK) {
			ar->ar_err = EAI_BADHINTS;
			break;
		}

		if (ai->ai_family != PF_UNSPEC &&
		    ai->ai_family != PF_INET &&
		    ai->ai_family != PF_INET6) {
			ar->ar_err = EAI_FAMILY;
			break;
		}

		if (ai->ai_socktype &&
		    ai->ai_socktype != SOCK_DGRAM  &&
		    ai->ai_socktype != SOCK_STREAM &&
		    ai->ai_socktype != SOCK_RAW) {
			ar->ar_err = EAI_SOCKTYPE;
			break;
		}

		if (ai->ai_protocol &&
		    ai->ai_protocol != IPPROTO_UDP  &&
		    ai->ai_protocol != IPPROTO_TCP) {
			ar->ar_err = EAI_PROTOCOL;
			break;
		}

		if (ai->ai_socktype == SOCK_RAW &&
		    aq->aq_servname != NULL) {
			ar->ar_err = EAI_SERVICE;
			break;
		}

		/* find the first valid combination */
		for (i = 0; matches[i].family != -1; i++)
			if (MATCH_FAMILY(ai->ai_family, i) &&
			    MATCH_SOCKTYPE(ai->ai_socktype, i) &&
			    MATCH_PROTO(ai->ai_protocol, i)) {
			aq->aq_match_idx = i;
			aq->aq_state = ASR_STATE_TRY_MATCH;
			break;
		}
		ar->ar_err = EAI_BADHINTS;
		break;

	case ASR_STATE_NEXT_MATCH:
		aq->aq_match_idx += 1;
		aq->aq_state = ASR_STATE_TRY_MATCH;
		break;

	case ASR_STATE_TRY_MATCH:
		if (matches[aq->aq_match_idx].family == -1) {
			if (aq->aq_aifirst) {
				ar->ar_ai = aq->aq_aifirst;
				aq->aq_aifirst = NULL;
				ar->ar_err = 0;
			} else
				ar->ar_err = EAI_NODATA;
			aq->aq_state = ASR_STATE_HALT;
			break;
		}

		ai = &aq->aq_hints;

		if (!(MATCH_FAMILY(ai->ai_family, aq->aq_match_idx) &&
		      MATCH_SOCKTYPE(ai->ai_socktype, aq->aq_match_idx) &&
		      MATCH_PROTO(ai->ai_protocol, aq->aq_match_idx))) {
			aq->aq_state = ASR_STATE_NEXT_MATCH;
			break;
		}

		family = matches[aq->aq_match_idx].family;

		/* check for negative cache */
		if ((family == PF_INET && aq->aq_noinet) ||
		    (family == PF_INET6 && aq->aq_noinet6)) {
			aq->aq_state = ASR_STATE_NEXT_MATCH;
			break;
		}

		/* check for addr-by-family cache */
		stop = 0;
		for(ac = aq->aq_addrcache; ac; ac = ac->aa_next) {
			if (ac->aa_sa.any.sa_family == family) {
				stop += 1;
				r = asr_add_sockaddr(aq,
					matches[aq->aq_match_idx].family,
					matches[aq->aq_match_idx].socktype,
					matches[aq->aq_match_idx].protocol,
					&ac->aa_sa.any, 0);
				if (r == -1) {
					ar->ar_err = EAI_MEMORY;
					aq->aq_state = ASR_STATE_HALT;
					break;
				}
				aq->aq_state = ASR_STATE_NEXT_MATCH;
			}
		}
		if (stop)
			break;

		if (aq->aq_hostname == NULL) {
			if (family == PF_INET)
				str = (aq->aq_flags & AI_PASSIVE) ? "0.0.0.0" : "127.0.0.1";
			else /* PF_INET6 */
				str = (aq->aq_flags & AI_PASSIVE) ? "::" : "::1";
			 /* can't fail */
			asr_sockaddr_parse(&aa.aa_sa.any, family, str);
			r = asr_add_sockaddr(aq,
				matches[aq->aq_match_idx].family,
				matches[aq->aq_match_idx].socktype,
				matches[aq->aq_match_idx].protocol,
				&aa.aa_sa.any, 1);
			if (r == -1) {
				ar->ar_err = EAI_MEMORY;
				aq->aq_state = ASR_STATE_HALT;
			} else
				aq->aq_state = ASR_STATE_NEXT_MATCH;
			break;
		}

		/* try numeric addresses */
		stop = 0;
		for (i = 0; families[i] != -1; i++) {
			if (asr_sockaddr_parse(&aa.aa_sa.any,
					       families[i],
					       aq->aq_hostname) == -1)
				continue;
			stop = 1;
			if (families[i] != family) {
				/* numeric address but not the right one */
				aq->aq_state = ASR_STATE_NEXT_MATCH;
				break;
			}
			r = asr_add_sockaddr(aq,
				matches[aq->aq_match_idx].family,
				matches[aq->aq_match_idx].socktype,
				matches[aq->aq_match_idx].protocol,
				&aa.aa_sa.any, 1);
			if (r == -1) {
				ar->ar_err = EAI_MEMORY;
				aq->aq_state = ASR_STATE_HALT;
			} else
				aq->aq_state = ASR_STATE_NEXT_MATCH;
			break;
		}
		if (stop)
			break;

		if (aq->aq_hints.ai_flags & AI_NUMERICHOST) {
			ar->ar_err = EAI_FAIL;
			aq->aq_state = ASR_STATE_HALT;
		}

		/* subquery for hostname */
		if ((aq->aq_subq = asr_query_host(aq->aq_asr,
					     aq->aq_hostname,
					     family)) == NULL) {
			ar->ar_err = EAI_MEMORY;
			aq->aq_state = ASR_STATE_HALT;
		}
		aq->aq_state = ASR_STATE_SUBQUERY;
		break;

	case ASR_STATE_SUBQUERY:
		switch ((r = asr_run(aq->aq_subq, ar))) {
		case ASR_NEED_READ:
		case ASR_NEED_WRITE:
			return (r);
		case ASR_YIELD:
			r = asr_add_sockaddr(aq,
				matches[aq->aq_match_idx].family,
				matches[aq->aq_match_idx].socktype,
				matches[aq->aq_match_idx].protocol,
				&ar->ar_sa.any, 1);
			free(ar->ar_cname);
			if (r == -1) {
				ar->ar_err = EAI_MEMORY;
				aq->aq_state = ASR_STATE_HALT;
			}
			break;
		case ASR_DONE:
			/* if nothing was found, make a negative cache for this family */
			if (ar->ar_count == 0) {
				if (matches[aq->aq_match_idx].family == PF_INET)
					aq->aq_noinet = 1;
				else if (matches[aq->aq_match_idx].family == PF_INET6)
					aq->aq_noinet6 = 1;
			}
			aq->aq_subq = NULL;
			aq->aq_state = ASR_STATE_NEXT_MATCH;
			break;
		}
		break;

	case ASR_STATE_HALT:
		ar->ar_count = aq->aq_count;
		ar->ar_errstr = (ar->ar_err) ? gai_strerror(ar->ar_err) : NULL;
		return (ASR_DONE);

	default:
		errx(1, "asr_run_addrinfo: unknown state");
	}}
}
