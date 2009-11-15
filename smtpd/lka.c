/*	$OpenBSD: lka.c,v 1.94 2009/11/13 11:27:51 jacekm Exp $	*/

/*
 * Copyright (c) 2008 Pierre-Yves Ritschard <pyr@openbsd.org>
 * Copyright (c) 2008 Gilles Chehade <gilles@openbsd.org>
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
#include <sys/wait.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <event.h>
#include <netdb.h>
#include <pwd.h>
#include <resolv.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "smtpd.h"

__dead void	lka_shutdown(void);
void		lka_sig_handler(int, short, void *);
void		lka_dispatch_parent(int, short, void *);
void		lka_dispatch_mfa(int, short, void *);
void		lka_dispatch_smtp(int, short, void *);
void		lka_dispatch_queue(int, short, void *);
void		lka_dispatch_runner(int, short, void *);
void		lka_dispatch_mta(int, short, void *);
void		lka_setup_events(struct smtpd *);
void		lka_disable_events(struct smtpd *);
void		lka_expand_pickup(struct smtpd *, struct lkasession *);
int		lka_expand_resume(struct smtpd *, struct lkasession *);
int		lka_resolve_node(struct smtpd *, char *tag, struct message *,
    struct delivery *, struct expand_node *);
int		lka_verify_mail(struct smtpd *, struct mailaddr *);
struct rule    *ruleset_match(struct smtpd *, char *tag, struct mailaddr *, struct sockaddr_storage *,
    struct cond **, int);
int		lka_resolve_recipient(struct smtpd *, struct lkasession *);
struct lkasession *lka_session_init(struct smtpd *, struct submit_status *);
void		lka_request_forwardfile(struct smtpd *, struct lkasession *, char *);
void		lka_clear_expandtree(struct expandtree *);
void		lka_clear_deliverylist(struct deliverylist *);
int		lka_encode_credentials(char *, size_t, char *);
int		lka_expand_format(char *, char *, struct message *, size_t);
void		lka_rcpt_action(struct smtpd *, char *, struct message *, struct mailaddr *);
void		lka_session_destroy(struct smtpd *, struct lkasession *);
void		lka_expansion_done(struct smtpd *, struct lkasession *);
void		lka_session_fail(struct smtpd *, struct lkasession *);
int		lka_message_to_delivery(struct delivery *, struct message *);

void
lka_sig_handler(int sig, short event, void *p)
{
	int status;
	pid_t pid;

	switch (sig) {
	case SIGINT:
	case SIGTERM:
		lka_shutdown();
		break;
	case SIGCHLD:
		do {
			pid = waitpid(-1, &status, WNOHANG);
		} while (pid > 0 || (pid == -1 && errno == EINTR));
		break;
	default:
		fatalx("lka_sig_handler: unexpected signal");
	}
}

void
lka_dispatch_parent(int sig, short event, void *p)
{
	struct smtpd		*env = p;
	struct imsgev		*iev;
	struct imsgbuf		*ibuf;
	struct imsg		 imsg;
	ssize_t			 n;

	iev = env->sc_ievs[PROC_PARENT];
	ibuf = &iev->ibuf;

	if (event & EV_READ) {
		if ((n = imsg_read(ibuf)) == -1)
			fatal("imsg_read_error");
		if (n == 0) {
			/* this pipe is dead, so remove the event handler */
			event_del(&iev->ev);
			event_loopexit(NULL);
			return;
		}
	}

	if (event & EV_WRITE) {
		if (msgbuf_write(&ibuf->w) == -1)
			fatal("msgbuf_write");
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("lka_dispatch_parent: imsg_get error");
		if (n == 0)
			break;

		switch (imsg.hdr.type) {
		case IMSG_CONF_START:
			if ((env->sc_rules_reload = calloc(1, sizeof(*env->sc_rules))) == NULL)
				fatal("mfa_dispatch_parent: calloc");
			if ((env->sc_maps_reload = calloc(1, sizeof(*env->sc_maps))) == NULL)
				fatal("mfa_dispatch_parent: calloc");
			TAILQ_INIT(env->sc_rules_reload);
			TAILQ_INIT(env->sc_maps_reload);
			break;
		case IMSG_CONF_RULE: {
			struct rule *rule = imsg.data;

			IMSG_SIZE_CHECK(rule);

			rule = calloc(1, sizeof(*rule));
			if (rule == NULL)
				fatal("mfa_dispatch_parent: calloc");
			*rule = *(struct rule *)imsg.data;

			TAILQ_INIT(&rule->r_conditions);
			TAILQ_INSERT_TAIL(env->sc_rules_reload, rule, r_entry);
			break;
		}
		case IMSG_CONF_CONDITION: {
			struct rule *r = TAILQ_LAST(env->sc_rules_reload, rulelist);
			struct cond *cond = imsg.data;

			IMSG_SIZE_CHECK(cond);

			cond = calloc(1, sizeof(*cond));
			if (cond == NULL)
				fatal("mfa_dispatch_parent: calloc");
			*cond = *(struct cond *)imsg.data;

			TAILQ_INSERT_TAIL(&r->r_conditions, cond, c_entry);
			break;
		}
		case IMSG_CONF_MAP: {
			struct map *m = imsg.data;

			IMSG_SIZE_CHECK(m);

			m = calloc(1, sizeof(*m));
			if (m == NULL)
				fatal("mfa_dispatch_parent: calloc");
			*m = *(struct map *)imsg.data;

			TAILQ_INIT(&m->m_contents);
			TAILQ_INSERT_TAIL(env->sc_maps_reload, m, m_entry);
			break;
		}
		case IMSG_CONF_RULE_SOURCE: {
			struct rule *rule = TAILQ_LAST(env->sc_rules_reload, rulelist);
			char *sourcemap = imsg.data;
			void *temp = env->sc_maps;

			/* map lookup must be done in the reloaded conf */
			env->sc_maps = env->sc_maps_reload;
			rule->r_sources = map_findbyname(env, sourcemap);
			if (rule->r_sources == NULL)
				fatalx("maps inconsistency");
			env->sc_maps = temp;
			break;
		}
		case IMSG_CONF_MAP_CONTENT: {
			struct map *m = TAILQ_LAST(env->sc_maps_reload, maplist);
			struct mapel *mapel = imsg.data;
			
			IMSG_SIZE_CHECK(mapel);
			
			mapel = calloc(1, sizeof(*mapel));
			if (mapel == NULL)
				fatal("mfa_dispatch_parent: calloc");
			*mapel = *(struct mapel *)imsg.data;

			TAILQ_INSERT_TAIL(&m->m_contents, mapel, me_entry);
			break;
		}
		case IMSG_CONF_END: {			
			/* switch and destroy old ruleset */
			if (env->sc_rules)
				purge_config(env, PURGE_RULES);
			if (env->sc_maps)
				purge_config(env, PURGE_MAPS);
			env->sc_rules = env->sc_rules_reload;
			env->sc_maps = env->sc_maps_reload;
			break;
		}
		case IMSG_PARENT_FORWARD_OPEN: {
			int fd;
			struct forward_req	*fwreq = imsg.data;
			struct lkasession	key;
			struct lkasession	*lkasession;
			struct message *message;

			IMSG_SIZE_CHECK(fwreq);

			key.id = fwreq->id;
			lkasession = SPLAY_FIND(lkatree, &env->lka_sessions, &key);
			if (lkasession == NULL)
				fatal("lka_dispatch_parent: lka session is gone");
			fd = imsg.fd;
			--lkasession->pending;

			strlcpy(lkasession->delivery.pw_name, fwreq->pw_name,
			    sizeof(lkasession->delivery.pw_name));
			lkasession->message = fwreq->message;
			lkasession->message.storage.delivery.flags |= F_DELIVERY_FORWARDED;

			/* received a descriptor, we have a forward file ... */
			if (fd != -1) {
				if (! forwards_get(fd, &lkasession->expandtree)) {
					lkasession->ss.code = 530;
					lkasession->flags |= F_ERROR;
				}
				close(fd);
				lka_expand_pickup(env, lkasession);
				break;
			}

			/* did not receive a descriptor but expected one ... */
			if (! fwreq->status) {
				lkasession->ss.code = 530;
				lkasession->flags |= F_ERROR;
				lka_expand_pickup(env, lkasession);
				break;
			}

			/* no forward file, convert pw_name to a struct delivery... */
			message = message_dup(&lkasession->message);
			message->id = generate_uid();
			strlcpy(message->storage.delivery.pw_name, fwreq->pw_name,
			    sizeof(message->storage.delivery.pw_name));

			TAILQ_INSERT_TAIL(&lkasession->deliverylist, message, entry);
			lka_expand_pickup(env, lkasession);
			break;
		}
		default:
			log_warnx("lka_dispatch_parent: got imsg %d",
			    imsg.hdr.type);
			fatalx("lka_dispatch_parent: unexpected imsg");
		}
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
}

void
lka_dispatch_mfa(int sig, short event, void *p)
{
	struct smtpd		*env = p;
	struct imsgev		*iev;
	struct imsgbuf		*ibuf;
	struct imsg		 imsg;
	ssize_t			 n;

	iev = env->sc_ievs[PROC_MFA];
	ibuf = &iev->ibuf;

	if (event & EV_READ) {
		if ((n = imsg_read(ibuf)) == -1)
			fatal("imsg_read_error");
		if (n == 0) {
			/* this pipe is dead, so remove the event handler */
			event_del(&iev->ev);
			event_loopexit(NULL);
			return;
		}
	}

	if (event & EV_WRITE) {
		if (msgbuf_write(&ibuf->w) == -1)
			fatal("msgbuf_write");
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("lka_dispatch_mfa: imsg_get error");
		if (n == 0)
			break;

		switch (imsg.hdr.type) {
		case IMSG_LKA_MAIL: {
			struct submit_status	*ss = imsg.data;
			struct mailaddr		*mailaddr;

			IMSG_SIZE_CHECK(ss);

			ss->code = 530;
			mailaddr = &ss->u.mailaddr;

			if (mailaddr->user[0] == '\0' && mailaddr->domain[0] == '\0')
				ss->code = 250;
			else
				if (lka_verify_mail(env, mailaddr))
					ss->code = 250;

			imsg_compose_event(iev, IMSG_LKA_MAIL, 0, 0, -1,
				ss, sizeof(*ss));

			break;
		}
		case IMSG_LKA_RULEMATCH: {
			struct submit_status	*ss = imsg.data;
			struct rule *rule;
			struct cond *cond;

			IMSG_SIZE_CHECK(ss);

			ss->code = 530;

			rule = ruleset_match(env, ss->message.storage.session.tag,
			    &ss->u.mailaddr, &ss->message.storage.session.ss, &cond,
			    ss->message.storage.flags & F_AUTHENTICATED);
			if (rule != NULL) {
				ss->code = 250;
				ss->message.rule = *rule;
				ss->message.condition = *cond;
			}
			imsg_compose_event(env->sc_ievs[PROC_MFA], IMSG_LKA_RULEMATCH, 0, 0, -1,
			    ss, sizeof(*ss));

			break;
		}
		case IMSG_LKA_RCPT: {
			struct submit_status	*ss = imsg.data;
			struct lkasession	*lkasession;
			struct delivery		*delivery;

			IMSG_SIZE_CHECK(ss);

			ss->code = 250;
			delivery = &ss->u.delivery;

			lkasession = lka_session_init(env, ss);

			if (! lka_resolve_recipient(env, lkasession))
				lka_session_fail(env, lkasession);
			else
				lka_expand_pickup(env, lkasession);

			break;
		}
		default:
			log_warnx("lka_dispatch_mfa: got imsg %d",
			    imsg.hdr.type);
			fatalx("lka_dispatch_mfa: unexpected imsg");
		}
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
}

void
lka_dispatch_mta(int sig, short event, void *p)
{
	struct smtpd		*env = p;
	struct imsgev		*iev;
	struct imsgbuf		*ibuf;
	struct imsg		 imsg;
	ssize_t			 n;

	iev = env->sc_ievs[PROC_MTA];
	ibuf = &iev->ibuf;

	if (event & EV_READ) {
		if ((n = imsg_read(ibuf)) == -1)
			fatal("imsg_read_error");
		if (n == 0) {
			/* this pipe is dead, so remove the event handler */
			event_del(&iev->ev);
			event_loopexit(NULL);
			return;
		}
	}

	if (event & EV_WRITE) {
		if (msgbuf_write(&ibuf->w) == -1)
			fatal("msgbuf_write");
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("lka_dispatch_mta: imsg_get error");
		if (n == 0)
			break;

		switch (imsg.hdr.type) {
		case IMSG_LKA_SECRET: {
			struct secret	*query = imsg.data;
			char		*secret = NULL;
			char		*map = "secrets";

			IMSG_SIZE_CHECK(query);

			secret = map_dblookupbyname(env, map, query->host);

			log_debug("secret for %s %s", query->host,
			    secret ? "found" : "not found");
			
			query->secret[0] = '\0';

			if (secret == NULL) {
				log_warnx("failed to lookup %s in the %s map",
				    query->host, map);
			} else if (! lka_encode_credentials(query->secret,
			    sizeof(query->secret), secret)) {
				log_warnx("parse error for %s in the %s map",
				    query->host, map);
			}

			imsg_compose_event(iev, IMSG_LKA_SECRET, 0, 0, -1, query,
			    sizeof(*query));
			free(secret);
			break;
		}

		case IMSG_DNS_MX:
		case IMSG_DNS_PTR: {
			struct dns	*query = imsg.data;

			IMSG_SIZE_CHECK(query);
			dns_async(env, iev, imsg.hdr.type, query);
			break;
		}

		default:
			log_warnx("lka_dispatch_mta: got imsg %d",
			    imsg.hdr.type);
			fatalx("lka_dispatch_mta: unexpected imsg");
		}
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
}

void
lka_dispatch_smtp(int sig, short event, void *p)
{
	struct smtpd		*env = p;
	struct imsgev		*iev;
	struct imsgbuf		*ibuf;
	struct imsg		 imsg;
	ssize_t			 n;

	iev = env->sc_ievs[PROC_SMTP];
	ibuf = &iev->ibuf;

	if (event & EV_READ) {
		if ((n = imsg_read(ibuf)) == -1)
			fatal("imsg_read_error");
		if (n == 0) {
			/* this pipe is dead, so remove the event handler */
			event_del(&iev->ev);
			event_loopexit(NULL);
			return;
		}
	}

	if (event & EV_WRITE) {
		if (msgbuf_write(&ibuf->w) == -1)
			fatal("msgbuf_write");
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("lka_dispatch_smtp: imsg_get error");
		if (n == 0)
			break;

		switch (imsg.hdr.type) {
		case IMSG_DNS_PTR: {
			struct dns	*query = imsg.data;

			IMSG_SIZE_CHECK(query);
			dns_async(env, iev, IMSG_DNS_PTR, query);
			break;
		}
		default:
			log_warnx("lka_dispatch_smtp: got imsg %d",
			    imsg.hdr.type);
			fatalx("lka_dispatch_smtp: unexpected imsg");
		}
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
}

void
lka_dispatch_queue(int sig, short event, void *p)
{
	struct smtpd		*env = p;
	struct imsgev		*iev;
	struct imsgbuf		*ibuf;
	struct imsg		 imsg;
	ssize_t			 n;

	iev = env->sc_ievs[PROC_QUEUE];
	ibuf = &iev->ibuf;

	if (event & EV_READ) {
		if ((n = imsg_read(ibuf)) == -1)
			fatal("imsg_read_error");
		if (n == 0) {
			/* this pipe is dead, so remove the event handler */
			event_del(&iev->ev);
			event_loopexit(NULL);
			return;
		}
	}

	if (event & EV_WRITE) {
		if (msgbuf_write(&ibuf->w) == -1)
			fatal("msgbuf_write");
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("lka_dispatch_queue: imsg_get error");
		if (n == 0)
			break;

		switch (imsg.hdr.type) {
		default:
			log_warnx("lka_dispatch_queue: got imsg %d",
			   imsg.hdr.type);
			fatalx("lka_dispatch_queue: unexpected imsg");
		}
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
}

void
lka_dispatch_runner(int sig, short event, void *p)
{
	struct smtpd		*env = p;
	struct imsgev		*iev;
	struct imsgbuf		*ibuf;
	struct imsg		 imsg;
	ssize_t			 n;

	iev = env->sc_ievs[PROC_RUNNER];
	ibuf = &iev->ibuf;

	if (event & EV_READ) {
		if ((n = imsg_read(ibuf)) == -1)
			fatal("imsg_read_error");
		if (n == 0) {
			/* this pipe is dead, so remove the event handler */
			event_del(&iev->ev);
			event_loopexit(NULL);
			return;
		}
	}

	if (event & EV_WRITE) {
		if (msgbuf_write(&ibuf->w) == -1)
			fatal("msgbuf_write");
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("lka_dispatch_runner: imsg_get error");
		if (n == 0)
			break;

		switch (imsg.hdr.type) {
		case IMSG_LKA_RULEMATCH: {
			struct rule *rule;
			struct cond *cond;
			struct message *message = imsg.data;

			rule = ruleset_match(env, message->storage.session.tag,
			    &message->storage.recipient, &message->storage.session.ss,
			    &cond, message->storage.flags & F_AUTHENTICATED);
			if (rule != NULL) {
				message->rule = *rule;
				message->condition = *cond;
				if (! IS_RELAY(*message)) {
					lka_message_to_delivery(&message->storage.delivery,
					    message);
				}
			}
			imsg_compose_event(env->sc_ievs[PROC_RUNNER],
			    IMSG_LKA_RULEMATCH, 0, 0, -1,
			    message, sizeof(*message));
			break;
		}
		default:
			log_warnx("lka_dispatch_runner: got imsg %d",
			    imsg.hdr.type);
			fatalx("lka_dispatch_runner: unexpected imsg");
		}
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
}

void
lka_shutdown(void)
{
	log_info("lookup agent exiting");
	_exit(0);
}

void
lka_setup_events(struct smtpd *env)
{
}

void
lka_disable_events(struct smtpd *env)
{
}

pid_t
lka(struct smtpd *env)
{
	pid_t		 pid;
	struct passwd	*pw;

	struct event	 ev_sigint;
	struct event	 ev_sigterm;
	struct event	 ev_sigchld;

	struct peer peers[] = {
		{ PROC_PARENT,	lka_dispatch_parent },
		{ PROC_MFA,	lka_dispatch_mfa },
		{ PROC_QUEUE,	lka_dispatch_queue },
		{ PROC_SMTP,	lka_dispatch_smtp },
		{ PROC_RUNNER,	lka_dispatch_runner },
		{ PROC_MTA,	lka_dispatch_mta }
	};

	switch (pid = fork()) {
	case -1:
		fatal("lka: cannot fork");
	case 0:
		break;
	default:
		return (pid);
	}

	purge_config(env, PURGE_EVERYTHING);

	pw = env->sc_pw;

	smtpd_process = PROC_LKA;
	setproctitle("%s", env->sc_title[smtpd_process]);

#ifndef DEBUG
	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("lka: cannot drop privileges");
#endif

	event_init();
	SPLAY_INIT(&env->lka_sessions);

	signal_set(&ev_sigint, SIGINT, lka_sig_handler, env);
	signal_set(&ev_sigterm, SIGTERM, lka_sig_handler, env);
	signal_set(&ev_sigchld, SIGCHLD, lka_sig_handler, env);
	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);
	signal_add(&ev_sigchld, NULL);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	config_pipes(env, peers, nitems(peers));
	config_peers(env, peers, nitems(peers));

	lka_setup_events(env);
	event_dispatch();
	lka_shutdown();

	return (0);
}

int
lka_verify_mail(struct smtpd *env, struct mailaddr *mailaddr)
{
	return 1;
}

int
lka_resolve_node(struct smtpd *env, char *tag, struct message *message,
    struct delivery *delivery, struct expand_node *expnode)
{
	struct delivery psave = *delivery;

	bzero(delivery, sizeof(struct delivery));

	switch (expnode->type) {
	case EXPAND_USERNAME: {
		struct mailaddr *mailaddr = &delivery->u.mailaddr;

		if (strlcpy(delivery->pw_name, expnode->u.username,
			sizeof(delivery->pw_name)) >= sizeof(delivery->pw_name))
			return 0;

		if (strlcpy(mailaddr->user, expnode->u.username,
			sizeof(mailaddr->user)) >= sizeof(mailaddr->user))
			return 0;

		if (psave.u.mailaddr.domain[0] != '\0') {
			if (strlcpy(mailaddr->domain, psave.u.mailaddr.domain,
				sizeof(mailaddr->domain)) >= sizeof(mailaddr->domain))
				return 0;
		}

		lka_rcpt_action(env, tag, message, mailaddr);
		message->storage.recipient = *mailaddr;

		log_debug("lka_resolve_node: resolved to address: %s@%s",
		    mailaddr->user, mailaddr->domain);
		log_debug("lka_resolve_node: resolved to local user: %s",
			delivery->pw_name);

		break;
	}

	case EXPAND_ADDRESS: {
		struct mailaddr *mailaddr = &delivery->u.mailaddr;

		log_debug("lka_resolve_node: node is address: %s@%s",
		    expnode->u.mailaddr.user, expnode->u.mailaddr.domain);

		if (strlcpy(mailaddr->user, expnode->u.mailaddr.user,
			sizeof(mailaddr->user)) >= sizeof(mailaddr->user))
			return 0;

		if (strlcpy(mailaddr->domain, expnode->u.mailaddr.domain,
			sizeof(mailaddr->domain)) >= sizeof(mailaddr->domain))
			return 0;

		lka_rcpt_action(env, tag, message, mailaddr);
		message->storage.recipient = *mailaddr;
		break;
	}

	case EXPAND_FILENAME: {

		log_debug("lka_resolve_node: node is filename: %s",
		    expnode->u.pathname);
		
		message->rule.r_action = A_FILENAME;
		strlcpy(message->storage.delivery.u.pathname, expnode->u.pathname,
		    sizeof(message->storage.delivery.u.pathname));
		break;
	}

	case EXPAND_MDA: {
		log_debug("lka_resolve_node: node is mda: %s",
		    expnode->u.mda);

		message->rule.r_action = A_EXT;
		strlcpy(message->storage.delivery.u.mda, expnode->u.mda + 2,
		    sizeof(message->storage.delivery.u.mda));
		message->storage.delivery.u.mda[strlen(message->storage.delivery.u.mda) - 1] = '\0';
		break;
	}

	case EXPAND_INVALID:
	case EXPAND_INCLUDE:
		fatalx("lka_resolve_node: unexpected type");
		break;
	}

	return 1;
}

void
lka_expand_pickup(struct smtpd *env, struct lkasession *lkasession)
{
	int	ret;

	/* we want to do five iterations of lka_expand_resume() but
	 * we need to be interruptible in case lka_expand_resume()
	 * has sent an imsg and expects an answer.
	 */
	ret = 0;
	while (! (lkasession->flags & F_ERROR) &&
	    ! lkasession->pending && lkasession->iterations < 5) {
		++lkasession->iterations;
		ret = lka_expand_resume(env, lkasession);
		if (ret == -1) {
			lkasession->ss.code = 530;
			lkasession->flags |= F_ERROR;
		}

		if (lkasession->pending || ret <= 0)
			break;
	}

	if (lkasession->pending)
		return;

	lka_expansion_done(env, lkasession);
}

int
lka_expand_resume(struct smtpd *env, struct lkasession *lkasession)
{
	u_int8_t done = 1;
	struct expand_node *expnode = NULL;

	RB_FOREACH(expnode, expandtree, &lkasession->expandtree) {

		/* this node has already been expanded, skip*/
		if (expnode->flags & F_EXPAND_DONE)
			continue;
		done = 0;

		/* convert node to delivery, then inherit flags from lkasession */
		log_debug("lka_expand_resume: #0");
		if (! lka_resolve_node(env, lkasession->message.storage.session.tag,
			&lkasession->message, &lkasession->delivery, expnode)) {
			log_debug("lka_expand_resume: generate a bounce for rcpt #1");
			return -1;
		}

		/* resolve delivery, eventually populating expandtree.
		 * we need to dup because delivery may be added to the deliverylist.
		 */
		if (! lka_resolve_recipient(env, lkasession)) {
			/* add a bounce to the delivery list*/
			log_debug("lka_expand_resume: generate a bounce for rcpt #2");
			return -1;
		}

		/* decrement refcount on this node and flag it as processed */
		expandtree_decrement_node(&lkasession->expandtree, expnode);
		expnode->flags |= F_EXPAND_DONE;
	}

	/* still not done after 5 iterations ? loop detected ... reject */
	if (!done && lkasession->iterations == 5) {
		return -1;
	}

	/* we're done expanding, no need for another iteration */
	if (RB_ROOT(&lkasession->expandtree) == NULL || done)
		return 0;

	return 1;
}

void
lka_expansion_done(struct smtpd *env, struct lkasession *lkasession)
{
	struct message *message;

	/* delivery list is empty OR expansion led to an error, reject */
	if (TAILQ_FIRST(&lkasession->deliverylist) == NULL ||
	    lkasession->flags & F_ERROR) {
		imsg_compose_event(env->sc_ievs[PROC_MFA], IMSG_LKA_RCPT, 0, 0,
		    -1, &lkasession->ss, sizeof(struct submit_status));
		goto done;
	}

	/* process the delivery list and submit envelopes to queue */
	while ((message = TAILQ_FIRST(&lkasession->deliverylist)) != NULL) {
		log_debug("MDA: %s", message->storage.delivery.u.mda);
		queue_submit_envelope(env, message);
		TAILQ_REMOVE(&lkasession->deliverylist, message, entry);
		free(message);
	}

	queue_commit_envelopes(env, &lkasession->message);

done:
	lka_clear_expandtree(&lkasession->expandtree);
	lka_clear_deliverylist(&lkasession->deliverylist);
	lka_session_destroy(env, lkasession);
}

int
lka_resolve_recipient(struct smtpd *env, struct lkasession *lkasession)
{
	struct message *message = &lkasession->message;

	if (IS_RELAY(lkasession->message)) {
		message = message_dup(message);
		message->id = generate_uid();
		message->storage.delivery.flags |= F_DELIVERY_RELAY;
		TAILQ_INSERT_TAIL(&lkasession->deliverylist, message, entry);
		return 1;
	}

	switch (message->condition.c_type) {
	case C_ALL:
	case C_NET:
	case C_DOM: {
		char username[MAXLOGNAME];
		char *sep;

		lowercase(username, message->storage.recipient.user,
		    sizeof(username));

		sep = strchr(username, '+');
		if (sep != NULL)
			*sep = '\0';

		if (aliases_exist(env, message->rule.r_amap, username)) {
			message->storage.delivery.flags |= F_DELIVERY_ALIAS;
			if (! aliases_get(env, message->rule.r_amap,
				&lkasession->expandtree, username)) {
				return 0;
			}
			return 1;
		}

		if (! lka_message_to_delivery(&message->storage.delivery, message))
			return 0;


		if (message->storage.delivery.flags & F_DELIVERY_FORWARDED) {
			message = message_dup(message);
			message->id = generate_uid();
			TAILQ_INSERT_TAIL(&lkasession->deliverylist, message, entry);
		}
		else {
			lkasession->message = *message;
			lka_request_forwardfile(env, lkasession,
			    message->storage.delivery.pw_name);
		}
		
		return 1;
	}
	case C_VDOM: {
		if (aliases_virtual_exist(env, message->condition.c_map,
			&message->storage.delivery.u.mailaddr)) {
			message->storage.delivery.flags |= F_DELIVERY_VIRTUAL;
			if (! aliases_virtual_get(env, message->condition.c_map,
				&lkasession->expandtree,
				&message->storage.delivery.u.mailaddr))
				return 0;
			return 1;
		}
		break;
	}
	default:
		fatalx("lka_resolve_recipient: unexpected type");
	}

	return 0;
}

void
lka_rcpt_action(struct smtpd *env, char *tag, struct message *message,
    struct mailaddr *mailaddr)
{
	struct rule *rule;
	struct cond *condition;
	
	if (mailaddr->domain[0] == '\0')
		(void)strlcpy(mailaddr->domain, env->sc_hostname,
		    sizeof (mailaddr->domain));

	rule = ruleset_match(env, tag, mailaddr, NULL, &condition, message->storage.flags & F_AUTHENTICATED);
	if (rule == NULL)
		return;

	message->rule = *rule;
	message->condition = *condition;
}

int
lkasession_cmp(struct lkasession *s1, struct lkasession *s2)
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

void
lka_clear_expandtree(struct expandtree *expandtree)
{
	struct expand_node *expnode;

	while ((expnode = RB_ROOT(expandtree)) != NULL) {
		expandtree_remove_node(expandtree, expnode);
		free(expnode);
	}
}

void
lka_clear_deliverylist(struct deliverylist *deliverylist)
{
	struct message *message;

	while ((message = TAILQ_FIRST(deliverylist)) != NULL) {
		TAILQ_REMOVE(deliverylist, message, entry);
		free(message);
	}
}

int
lka_encode_credentials(char *dst, size_t size, char *user)
{
	char	*pass, *buf;
	int	 buflen;

	if ((pass = strchr(user, ':')) == NULL)
		return 0;
	*pass++ = '\0';

	if ((buflen = asprintf(&buf, "%c%s%c%s", '\0', user, '\0', pass)) == -1)
		fatal(NULL);

	if (__b64_ntop((unsigned char *)buf, buflen, dst, size) == -1) {
		free(buf);
		return 0;
	}

	free(buf);
	return 1;
}

struct lkasession *
lka_session_init(struct smtpd *env, struct submit_status *ss)
{
	struct lkasession *lkasession;

	lkasession = calloc(1, sizeof(struct lkasession));
	if (lkasession == NULL)
		fatal("lka_session_init: calloc");

	lkasession->id = generate_uid();
	lkasession->message = ss->message;
	lkasession->ss = *ss;
	
	RB_INIT(&lkasession->expandtree);
	TAILQ_INIT(&lkasession->deliverylist);
	SPLAY_INSERT(lkatree, &env->lka_sessions, lkasession);

	return lkasession;
}

void
lka_session_fail(struct smtpd *env, struct lkasession *lkasession)
{
	lkasession->ss.code = 530;
	imsg_compose_event(env->sc_ievs[PROC_MFA], IMSG_LKA_RCPT, 0, 0, -1,
	    &lkasession->ss, sizeof(lkasession->ss));
	lka_session_destroy(env, lkasession);
}

void
lka_session_destroy(struct smtpd *env, struct lkasession *lkasession)
{
	SPLAY_REMOVE(lkatree, &env->lka_sessions, lkasession);
	free(lkasession);
}

void
lka_request_forwardfile(struct smtpd *env, struct lkasession *lkasession, char *username)
{
	struct forward_req	 fwreq;

	fwreq.id = lkasession->id;
	fwreq.message = lkasession->message;
	(void)strlcpy(fwreq.pw_name, username, sizeof(fwreq.pw_name));
	imsg_compose_event(env->sc_ievs[PROC_PARENT], IMSG_PARENT_FORWARD_OPEN, 0, 0, -1,
	    &fwreq, sizeof(fwreq));
	++lkasession->pending;
}

int
lka_message_to_delivery(struct delivery *delivery, struct message *message)
{
	delivery->pw = getpwnam(message->storage.recipient.user);
	if (delivery->pw == NULL)
		return 0;

	strlcpy(delivery->pw_name, delivery->pw->pw_name, sizeof(delivery->pw_name));
	delivery->flags |= F_DELIVERY_ACCOUNT;

	switch (message->rule.r_action) {
	case A_MBOX:
		delivery->type = T_DELIVERY_MBOX;
		break;
	case A_MAILDIR:
		delivery->type = T_DELIVERY_MBOX;
		if (! lka_expand_format(delivery->u.pathname, delivery->u.pathname,
			message, sizeof(delivery->u.pathname)))
			return 0;
		break;
	case A_FILENAME:
		delivery->type = T_DELIVERY_FILENAME;
		if (! lka_expand_format(delivery->u.pathname, delivery->u.pathname,
			message, sizeof(delivery->u.pathname)))
			return 0;
		break;
	case A_EXT:
		delivery->type = T_DELIVERY_MDA;
		if (! lka_expand_format(delivery->u.mda, delivery->u.mda,
			message, sizeof(delivery->u.mda)))
			return 0;
		break;
	default:
		fatal("lka_message_to_delivery: unknown delivery type");
	}

	return 1;
}

int
lka_expand_format(char *dest, char *src, struct message *message, size_t len)
{
	char *p, *pbuf;
	size_t ret;

	pbuf = dest;
	for (p = src; *p != '\0'; ++p) {
		ret = 0;
		if (!IS_RELAY(*message) && strncmp(p, "~/", 2) == 0) {
			ret += strlcat(dest, message->storage.delivery.pw->pw_dir, len);
			pbuf += ret;
			continue;
		}

		if (*p == '%') {
			switch (*(p + 1)) {
			case 'u':
				ret += strlcat(dest, message->storage.delivery.pw_name,
				    len);
				pbuf += ret;
				break;
			case 'a':
				ret += strlcat(dest, message->storage.recipient.user,
				    len);
				pbuf += ret;
				break;
			case 'd':
				ret += strlcat(dest, message->storage.recipient.domain,
				    len);
				pbuf += ret;
				break;
			default:
				return 0;
			}
		}
		if (ret) {
			if (ret >= len)
				return 0;
			continue;
		}

		*pbuf++ = *p;
	}

	return 1;
}

SPLAY_GENERATE(lkatree, lkasession, nodes, lkasession_cmp);
