#include <sys/types.h>
#include <sys/uio.h>

#include <netinet/in.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#include "log.h"
#include "filter_api.h"

#define USER_TAB_NAME "users"
#define USER_COL_NAME "name"
#define DOMAIN_TAB_NAME "domains"
#define DOMAIN_COL_NAME "domain"

extern char *ss_to_text(const struct sockaddr_storage *);
int match_domain(char *, char *);
int match_rcpt(char *, char *);
enum filter_status rcpt_cb(uint64_t, struct filter_rcpt *, void *);

struct filter_user_sql_arg {
	int ok;
	char *email;
};
int
match_domain(char *rcpt, char *domain)
{
	char *rcptdomain, *tmp;
	tmp = strdup(rcpt);

	rcptdomain = strchr(tmp, '@');
	if (rcptdomain == NULL)
		return 0;

	if (strncasecmp(rcptdomain+1, domain, strlen(domain)) == 0)
		return 1;

	return 0;
}
int
match_rcpt(char *rcpt, char *userline)
{
	if (strncasecmp(rcpt, userline, strlen(userline)) == 0)
		return 1;
	/* XXX more logic for wildcard domains etc */
	/* if (userline[0] == '@') { */
	return 0;
}

static int
sql_domain_callback( void *arg, int argc, char **argv, char **colname )
{
	int i;
	struct filter_user_sql_arg *user_sql_arg = arg;
	log_debug("sql_domain_callback: starting email %s", user_sql_arg->email);
	for (i=0; i<argc; i++) {
		if (strncmp(DOMAIN_COL_NAME, colname[i],
		    strlen(DOMAIN_COL_NAME)) == 0) {
			log_debug("%d: Comparing db user %s with email %s", i,
			    argv[i], user_sql_arg->email);
			if (match_domain(user_sql_arg->email, argv[i])) {
				log_info("matched domain %s!", argv[i]);
				user_sql_arg->ok = 1;
				break;
			}
			break;
		}
	}
	log_debug("rcpt %s: ok = %d", user_sql_arg->email, user_sql_arg->ok);
	return (0);
}

static int
sql_user_callback( void *arg, int argc, char **argv, char **colname )
{
	int i;
	struct filter_user_sql_arg *user_sql_arg = arg;
	log_debug("sql_user_callback: starting email %s", user_sql_arg->email);
	for (i=0; i<argc; i++) {
		if (strncmp(USER_COL_NAME, colname[i], strlen(USER_COL_NAME))
		    == 0) {
			log_debug("%d: Comparing db user %s with email %s", i,
			    argv[i], user_sql_arg->email);
			if (match_rcpt(user_sql_arg->email, argv[i])) {
				log_info("matched user %s!", argv[i]);
				user_sql_arg->ok = 1;
				break;
			}
			break;
		}
	}
	log_debug("rcpt %s: ok = %d", user_sql_arg->email, user_sql_arg->ok);
	return (0);
}

enum filter_status
rcpt_cb(uint64_t id, struct filter_rcpt *rcpt, void *p)
{
	char *errmsg = NULL;
	int rc;
	struct filter_user_sql_arg user_sql_arg;
	sqlite3 *db;

	user_sql_arg.ok = 0;

	asprintf(&user_sql_arg.email, "%s@%s", rcpt->user, rcpt->domain);

	log_info("[%llx] RCPT: %s", id, user_sql_arg.email);

	rc = sqlite3_open("/etc/mail/users.db", &db);
	if ( rc ) {
		log_info("Can't open database: %s", sqlite3_errmsg(db));
		/* XXX is this right? */
		return STATUS_ACCEPT;
	}

	/*
	 * check if the rcpt falls in a domain we need to check users for,
	 * if not, ACCEPT because its likely going to be an outbound relay
	 * mail etc
	 *
	 */
	rc = sqlite3_exec(db, "select * from " DOMAIN_TAB_NAME,
	    sql_domain_callback, (void *)&user_sql_arg, &errmsg);
	if (rc != SQLITE_OK) {
		log_info("SQL error: %s", errmsg);
		sqlite3_free(errmsg);
	}
	if (user_sql_arg.ok == 0)
		return STATUS_ACCEPT;

	user_sql_arg.ok = 0;

	rc = sqlite3_exec(db, "select * from " USER_TAB_NAME,
	    sql_user_callback, (void *)&user_sql_arg, &errmsg);
	if (rc != SQLITE_OK) {
		log_info("SQL error: %s", errmsg);
		sqlite3_free(errmsg);
	}
	free(user_sql_arg.email);

	if (user_sql_arg.ok == 0)
		return STATUS_REJECT;

	sqlite3_close(db);

	return STATUS_ACCEPT;
}

int
main(int argc, char *argv[])
{
	log_init(0);
	log_verbose(1);

	log_info("Starting filter!");

	filter_init();
	filter_register_rcpt_callback(rcpt_cb, NULL);

	log_info("Starting filter_loop!");
	filter_loop();

	return EXIT_SUCCESS;
}
