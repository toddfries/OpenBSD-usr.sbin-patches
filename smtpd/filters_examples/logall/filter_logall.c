#include <sys/types.h>
#include <sys/uio.h>

#include <netinet/in.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>

#include "filter_api.h"

extern char *ss_to_text(const struct sockaddr_storage *);

struct filter_all_arg
{
	FILE *f;
};

enum filter_status
connect_cb(uint64_t id, struct filter_connect *f_connect, void *p)
{
	struct filter_all_arg	*fda = p;

	fprintf(fda->f, "[%llx] CONNECT: %s (%s)\n", id, f_connect->hostname, ss_to_text(&f_connect->hostaddr));

	fflush(fda->f);
	return STATUS_ACCEPT;
}

enum filter_status
helo_cb(uint64_t id, struct filter_helo *helo, void *p)
{
	struct filter_all_arg	*fda = p;

	fprintf(fda->f, "[%llx] HELO: %s\n", id, helo->helohost);

	fflush(fda->f);
	return STATUS_ACCEPT;
}

enum filter_status
mail_cb(uint64_t id, struct filter_mail *mail, void *p)
{
	struct filter_all_arg	*fda = p;

	fprintf(fda->f, "[%llx] MAIL: %s@%s\n", id, mail->user, mail->domain);

	fflush(fda->f);
	return STATUS_ACCEPT;
}

enum filter_status
rcpt_cb(uint64_t id, struct filter_rcpt *rcpt, void *p)
{
	struct filter_all_arg	*fda = p;

	fprintf(fda->f, "[%llx] RCPT: %s@%s\n", id, rcpt->user, rcpt->domain);

	fflush(fda->f);
	return STATUS_ACCEPT;
}

enum filter_status
dataline_cb(uint64_t id, struct filter_dataline *dataline, void *p)
{
	struct filter_all_arg	*fda = p;

	fprintf(fda->f, "[%llx] DATALINE: %s\n", id,
		dataline->line);
	
	fflush(fda->f);
	return STATUS_ACCEPT;
}

enum filter_status
quit_cb(uint64_t id, void *p)
{
	struct filter_all_arg	*fda = p;

	fprintf(fda->f, "[%llx] QUIT\n", id);

	fflush(fda->f);
	return STATUS_ACCEPT;
}

enum filter_status
close_cb(uint64_t id, void *p)
{
	struct filter_all_arg	*fda = p;

	fprintf(fda->f, "[%llx] CLOSE\n", id);

	fflush(fda->f);
	return STATUS_ACCEPT;
}

enum filter_status
rset_cb(uint64_t id, void *p)
{
	struct filter_all_arg	*fda = p;

	fprintf(fda->f, "[%llx] RSET\n", id);

	fflush(fda->f);
	return STATUS_ACCEPT;
}

int
main(int argc, char *argv[])
{
	FILE			*f;
	struct filter_all_arg	*fda;

	f = fopen("/tmp/smtpd-filter.log", "a");

	if (f == NULL)
		errx(EXIT_FAILURE, "fopen");

	if ((fda = calloc(1, sizeof(struct filter_all_arg))) == NULL)
		errx(EXIT_FAILURE, "calloc");

	fda->f = f;
	
	fprintf(fda->f, "Starting filter!\n");

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
	fflush(fda->f);
	filter_loop();

	fflush(fda->f);
	fclose(fda->f);
	free(fda);

	return EXIT_SUCCESS;
}
