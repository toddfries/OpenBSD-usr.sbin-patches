#include <sys/types.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/param.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <err.h>
#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "smtpd.h"
#include "log.h"

extern char *ss_to_text(const struct sockaddr_storage *);

#define CASE(x) case x : return #x

const char *
dns_to_str(int type)
{
	static char	 buf[32];

	switch(type) {
	CASE(DNS_OK);
	CASE(DNS_RETRY);
	CASE(DNS_EINVAL);
	CASE(DNS_ENONAME);
	CASE(DNS_ENOTFOUND);
	default:
		snprintf(buf, sizeof(buf), "DNS_??? (%d)", type);

		return buf;
	}
}

struct filter_dnsbl_arg
{
	FILE *f;
};

char *
dnsbl_query_to_str(char *dnsbl_host, struct sockaddr_storage *ss)
{
	static char	 buf[NI_MAXHOST + 5];
	char		*p;
	in_addr_t	 addr;

	buf[0] = '\0';
	p = buf;

	if (ss->ss_family == PF_INET)
	{
		addr = ((struct sockaddr_in *)ss)->sin_addr.s_addr;
		addr = ntohl(addr);
		bsnprintf(p, NI_MAXHOST,
		    "%d.%d.%d.%d.%s",
		    addr & 0xff,
		    (addr >> 8) & 0xff,
		    (addr >> 16) & 0xff,
		    (addr >> 24) & 0xff,
		    dnsbl_host);
	}

	return (buf);
}


enum filter_status
dns_lookup_host_cb(uint64_t id, struct dns *dns, void *p)
{
	struct filter_dnsbl_arg	*fda = p;
	enum filter_status 	 ret = STATUS_ACCEPT;

	switch (dns->type) {
	case IMSG_DNS_HOST:
		fprintf(fda->f, "IMSG_DNS_HOST\n");
		ret = STATUS_WAITING;
		break;
	case IMSG_DNS_HOST_END:
		fprintf(fda->f, "IMSG_DNS_HOST_END\n");
		if (dns->error == DNS_ENOTFOUND)
			ret = STATUS_ACCEPT;
		else
			ret = STATUS_REJECT;
		break;
	default:
		fprintf(fda->f, "IMSG_DNS_??\n");
		break;
	}

	fprintf(fda->f, "[%llx] DNS_LOOKUP_HOST %s = %s (error=%s) --> %s\n", id,
		dns->host,
		ss_to_text(&dns->ss),
		dns_to_str(dns->error),
		(dns->type != IMSG_DNS_HOST_END) ? "STATUS_WAITING" :
		(dns->error == DNS_ENOTFOUND) ? "STATUS_ACCEPT" : "STATUS_REJECT");

	fflush(fda->f);

	return (ret);
}

enum filter_status
connect_cb(uint64_t id, struct filter_connect *f_connect, void *p)
{
	struct filter_dnsbl_arg	*fda = p;
	char			*dnsbl_query;
	enum filter_status	 ret;

	fprintf(fda->f, "[%llx] CONNECT: %s (%s)\n", id, f_connect->hostname, ss_to_text(&f_connect->hostaddr));

	dnsbl_query = dnsbl_query_to_str("dnsbl.sorbs.net", &f_connect->hostaddr);

	if (dnsbl_query[0] == '\0') {
		fprintf(fda->f, "[%llx] No DNSBL query to do\n", id);
		ret = STATUS_ACCEPT;
	} else {
		fprintf(fda->f, "[%llx] querying %s\n", id, dnsbl_query);

		fltapi_dns_lookup_host(dnsbl_query, dns_lookup_host_cb, fda);

		ret = STATUS_WAITING;
	}

	fflush(fda->f);
	return ret;
}

enum filter_status
helo_cb(uint64_t id, struct filter_helo *helo, void *p)
{
	struct filter_dnsbl_arg	*fda = p;

	fprintf(fda->f, "[%llx] HELO: %s\n", id, helo->helohost);

	//fltapi_dns_lookup_host("google.com", dns_lookup_host_cb, fda);

	fflush(fda->f);
//	return STATUS_WAITING;
	return STATUS_ACCEPT;
}

enum filter_status
mail_cb(uint64_t id, struct filter_mail *mail, void *p)
{
	struct filter_dnsbl_arg	*fda = p;

	fprintf(fda->f, "[%llx] MAIL: %s@%s\n", id, mail->user, mail->domain);
	/* fltapi_dns_lookup_host("google.com", dns_lookup_host_cb, fda); */

	fflush(fda->f);
	return STATUS_ACCEPT;
}

enum filter_status
rcpt_cb(uint64_t id, struct filter_rcpt *rcpt, void *p)
{
	struct filter_dnsbl_arg	*fda = p;

	fprintf(fda->f, "[%llx] RCPT: %s@%s\n", id, rcpt->user, rcpt->domain);

	fflush(fda->f);
	return STATUS_ACCEPT;
}

enum filter_status
dataline_cb(uint64_t id, struct filter_dataline *dataline, void *p)
{
	struct filter_dnsbl_arg	*fda = p;

	fprintf(fda->f, "[%llx] DATALINE: %s\n", id,
		dataline->line);
	
	fflush(fda->f);
	return STATUS_ACCEPT;
}

enum filter_status
quit_cb(uint64_t id, void *p)
{
	struct filter_dnsbl_arg	*fda = p;

	fflush(fda->f);
	fprintf(fda->f, "[%llx] QUIT\n", id);

	fflush(fda->f);
	return STATUS_ACCEPT;
}

enum filter_status
close_cb(uint64_t id, void *p)
{
	struct filter_dnsbl_arg	*fda = p;

	fflush(fda->f);
	fprintf(fda->f, "[%llx] CLOSE\n", id);

	fflush(fda->f);
	return STATUS_ACCEPT;
}

enum filter_status
rset_cb(uint64_t id, void *p)
{
	struct filter_dnsbl_arg	*fda = p;

	fprintf(fda->f, "[%llx] RSET\n", id);

	fflush(fda->f);
	return STATUS_ACCEPT;
}

enum filter_status
dns_lookup_mx_cb(uint64_t id, struct dns *dns, void *p)
{
	struct filter_dnsbl_arg	*fda = p;

	fprintf(fda->f, "[%llx] DNS_LOOKUP_MX\n", id);

	fflush(fda->f);
	return STATUS_ACCEPT;
}

enum filter_status
dns_lookup_ptr_cb(uint64_t id, struct dns *dns, void *p)
{
	struct filter_dnsbl_arg	*fda = p;

	fprintf(fda->f, "[%llx] DNS_LOOKUP_PTR\n", id);

	fflush(fda->f);
	return STATUS_ACCEPT;
}

int
main(int argc, char *argv[])
{
	FILE			*f;
	struct filter_dnsbl_arg	*fda;

	f = fopen("/tmp/smtpd-filter.log", "a");

	if (f == NULL)
		errx(EXIT_FAILURE, "fopen");

	if ((fda = calloc(1, sizeof(struct filter_dnsbl_arg))) == NULL)
		errx(EXIT_FAILURE, "calloc");

	fda->f = f;
	
	fprintf(fda->f, "Starting filter!\n");
	printf("Starting filter!\n");
	filter_init();
	filter_register_connect_callback(connect_cb, fda);
	filter_register_helo_callback(helo_cb, fda);
	filter_register_ehlo_callback(helo_cb, fda);
	filter_register_mail_callback(mail_cb, fda);
	filter_register_rcpt_callback(rcpt_cb, fda);
	filter_register_dataline_callback(dataline_cb, fda);
	filter_register_quit_callback(quit_cb, fda);
	filter_register_close_callback(close_cb, fda);
	filter_register_rset_callback(rset_cb, fda);

	fprintf(fda->f, "Starting filter_loop!\n");
	printf("Starting filter_loop!\n");
	filter_loop();

	printf("fflush!\n");
	fflush(fda->f);

	fprintf(fda->f, "fclose!\n");
	printf("fclose!\n");

	fclose(fda->f);
	free(fda);

	return 0;
}
