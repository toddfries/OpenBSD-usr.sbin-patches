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
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <scsi/iscsi.h>
#include <scsi/scsi_all.h>
#include <dev/vscsivar.h>

#include <event.h>
#include <stdlib.h>
#include <string.h>

#include "iscsid.h"
#include "log.h"

struct initiator *initiator;

struct initiator *
initiator_init(void)
{
	if (!(initiator = calloc(1, sizeof(*initiator))))
		fatal("initiator_init");

	initiator->isid_base = arc4random_uniform(0xffffff) | ISCSI_ISID_RAND;
	initiator->isid_qual = arc4random_uniform(0xffff);
	TAILQ_INIT(&initiator->sessions);
	return (initiator);
}

struct session *
initiator_t2s(u_int target)
{
	struct session *s;

	TAILQ_FOREACH(s, &initiator->sessions, entry) {
		if (s->target == target)
			return s;
	}
	return NULL;
}

void
session_new(struct initiator *i, const char *ip, const char *port)
{
	struct session *s;

	if (!(s = calloc(1, sizeof(*s))))
		fatal("session_new");
	
	/* use the same qualifier unless there is a conflict */
	s->isid_qual = i->isid_qual;
	s->cmdseqnum = arc4random();
	s->itt = arc4random();
	s->initiator = i;
	s->target = i->target++;

	TAILQ_INSERT_HEAD(&i->sessions, s, entry);
	TAILQ_INIT(&s->connections);
	TAILQ_INIT(&s->tasks);

	log_debug("new connection to %s port %s", ip, port);
	conn_new(s, ip, port);

	/* login task, enumeration task, logout task */
}

void
session_task_issue(struct session *s, struct task *t)
{
	TAILQ_INSERT_TAIL(&s->tasks, t, entry);
	session_schedule(s);
}

void
session_schedule(struct session *s)
{
	struct task *t = TAILQ_FIRST(&s->tasks);
	struct connection *c;

	if (!t)
		return;

	/* XXX IMMEDIATE TASK NEED SPECIAL HANDLING !!!! */

	/* wake up a idle connection or a not busy one */
	/* XXX this needs more work as it makes the daemon go wrooOOOMM */
	TAILQ_REMOVE(&s->tasks, t, entry);
	TAILQ_FOREACH(c, &s->connections, entry)
		if (conn_task_issue(c, t))
			return;
	/* all connections are busy readd task to the head */
	TAILQ_INSERT_HEAD(&s->tasks, t, entry);
}

struct task_login {
	struct task		 task;
	struct connection	*c;
	u_int16_t		 tsih;
	u_int8_t		 stage;
};

struct pdu *initiator_login_build(struct task_login *, struct kvp *);
void	initiator_login_cb(struct connection *, void *, struct pdu *);

void	initiator_discovery(struct session *);
void	initiator_discovery_cb(struct connection *, void *, struct pdu *);
struct pdu *initiator_text_build(struct task *, struct session *, struct kvp *);

void
initiator_login(struct connection *c)
{
	struct task_login *tl;
	struct pdu *p;
	struct kvp kvp[] = {
		{ "AuthMethod", "None" },
		{ "InitiatorName", "iqn.t41.hostid.66d48107:plemplem" },
		{ "TargetName", "iqn.2001-05.com.equallogic:0-8a0906-ca7423603-900e8298d6f4b7a1-test0" },
//		{ "SessionType", "Discovery" },
		{ NULL, NULL }
	};

	if (!(tl = calloc(1, sizeof(*tl)))) {
		log_warn("initiator_login");
		conn_fail(c);
		return;
	}
	tl->c = c;
	tl->stage = ISCSI_LOGIN_STG_SECNEG;

	if (!(p = initiator_login_build(tl, kvp))) {
		log_warnx("initiator_login_build failed");
		conn_fail(c);
		return;
	}

	task_init(&tl->task, c->session, 1, tl, initiator_login_cb);
	task_pdu_add(&tl->task, p);
	/* XXX this is wrong, login needs to run on a specific connection */
	session_task_issue(c->session, &tl->task);
}

struct pdu *
initiator_login_build(struct task_login *tl, struct kvp *kvp)
{
	struct pdu *p;
	struct iscsi_pdu_login_request *lreq;
	int n;

	if (!(p = pdu_new()))
		return NULL;
	if (!(lreq = pdu_gethdr(p, 1)))
		return NULL;

	lreq->opcode = ISCSI_OP_LOGIN_REQUEST | ISCSI_OP_F_IMMEDIATE;
	if (tl->stage == ISCSI_LOGIN_STG_SECNEG)
		lreq->flags = ISCSI_LOGIN_F_T |
		    ISCSI_LOGIN_F_CSG(ISCSI_LOGIN_STG_OPNEG) |
		    ISCSI_LOGIN_F_NSG(ISCSI_LOGIN_STG_FULL);
	else if (tl->stage == ISCSI_LOGIN_STG_OPNEG)
		lreq->flags = ISCSI_LOGIN_F_T |
		    ISCSI_LOGIN_F_CSG(ISCSI_LOGIN_STG_OPNEG) |
		    ISCSI_LOGIN_F_NSG(ISCSI_LOGIN_STG_FULL);

	lreq->isid_base = htonl(tl->c->session->initiator->isid_base);
	lreq->isid_qual = htons(tl->c->session->isid_qual);
	lreq->tsih = tl->tsih;
	lreq->cid = htons(tl->c->cid);
	lreq->expstatsn = htonl(tl->c->expstatsn);

	if ((n = text_to_pdu(kvp, p)) == -1)
		return NULL;
	n = htonl(n);
	bcopy(&n, &lreq->ahslen, sizeof(n));

	return p;
}

void
initiator_login_cb(struct connection *c, void *arg, struct pdu *p)
{
	struct task_login *tl = arg;
	struct iscsi_pdu_login_response *lresp;

	lresp = pdu_gethdr(p, 0);
	log_pdu(p);
	if (ISCSI_PDU_OPCODE(lresp->opcode) != ISCSI_OP_LOGIN_RESPONSE) {
		log_debug("Unkown crap");
	}

	task_cleanup(&tl->task, c);
	initiator_discovery(c->session);
	vscsi_event(VSCSI_REQPROBE, c->session->target, 0);
}

void
initiator_discovery(struct session *s)
{
	struct task *t;
	struct pdu *p;
	struct kvp kvp[] = {
		{ "SendTargets", "All" },
		{ NULL, NULL }
	};

	if (!(t = calloc(1, sizeof(*t)))) {
		log_warn("initiator_discovery");
		return;
	}

	if (!(p = initiator_text_build(t, s, kvp))) {
		log_warnx("initiator_text_build failed");
		return;
	}

	task_init(t, s, 0, t, initiator_discovery_cb);
	task_pdu_add(t, p);
	session_task_issue(s, t);
}

struct pdu *
initiator_text_build(struct task *t, struct session *s, struct kvp *kvp)
{
	struct pdu *p;
	struct iscsi_pdu_text_request *lreq;
	int n;

	if (!(p = pdu_new()))
		return NULL;
	if (!(lreq = pdu_gethdr(p, 1)))
		return NULL;

	lreq->opcode = ISCSI_OP_TEXT_REQUEST;
	lreq->flags = ISCSI_TEXT_F_F;
	lreq->ttt = 0xffffffff;

	if ((n = text_to_pdu(kvp, p)) == -1)
		return NULL;
	n = htonl(n);
	bcopy(&n, &lreq->ahslen, sizeof(n));

	return p;
}

void
initiator_discovery_cb(struct connection *c, void *arg, struct pdu *p)
{
	log_debug("DISCO DISCO");
	log_pdu(p);
}
