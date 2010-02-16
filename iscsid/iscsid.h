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

#define ISCSI_DEVICE	"/dev/vscsi0"
#define ISCSID_USER	"_iscsid"

#define PDU_READ_SIZE	(256 * 1024)
#define PDU_MAXIOV	4
#define PDU_WRIOV	(PDU_MAXIOV * 8)


TAILQ_HEAD(session_head, session);
TAILQ_HEAD(connection_head, connection);
TAILQ_HEAD(pduq, pdu);
TAILQ_HEAD(taskq, task);

struct initiator {
	struct session_head	sessions;
	u_int			 target;
	u_int32_t		isid_base;	/* only 24 bits */
	u_int16_t		isid_qual;
};

/* as in tcp_seq.h */
#define SEQ_LT(a,b)     ((int)((a)-(b)) < 0)
#define SEQ_LEQ(a,b)    ((int)((a)-(b)) <= 0)
#define SEQ_GT(a,b)     ((int)((a)-(b)) > 0)
#define SEQ_GEQ(a,b)    ((int)((a)-(b)) >= 0)


#define	CONN_FREE		0x0001
#define	CONN_XPT_WAIT		0x0002
#define	CONN_XPT_UP		0x0004
#define	CONN_IN_LOGIN		0x0008
#define	CONN_LOGGED_IN		0x0010
#define	CONN_IN_LOGOUT		0x0020
#define	CONN_LOGOUT_REQ		0x0040
#define	CONN_CLEANUP_WAIT	0x0080
#define	CONN_IN_CLEANUP		0x0100
#define CONN_ANYSTATE		0xffff

enum c_event {
	CONN_EV_FAIL,
	CONN_EV_CONNECT,
	CONN_EV_CONNECTED,
	CONN_EV_CLOSE
};

struct pdu_readbuf {
	char		*buf;
	size_t		 size;
	size_t		 rpos;
	size_t		 wpos;
	struct pdu	*wip;
};

struct session {
	TAILQ_ENTRY(session)	 entry;
	struct connection_head	 connections;
	struct taskq		 tasks;
	struct initiator	*initiator;
	u_int16_t		 isid_qual;	/* inherited from initiator */
	u_int16_t		 tsih;		/* target session id handle */
	u_int32_t		 cmdseqnum;
	u_int32_t		 itt;
	u_int			 target;
};

struct connection {
	struct event		 ev;
	struct event		 wev;
	struct sockaddr_storage	 target;
	TAILQ_ENTRY(connection)	 entry;
	struct pdu_readbuf	 prbuf;
	struct pduq		 pdu_w;
	struct taskq		 tasks;
	struct session		*session;
	u_int32_t		 expstatsn;
	int			 state;
	int			 fd;
	u_int16_t		 cid;	/* conection id */
};

struct pdu {
	TAILQ_ENTRY(pdu)	 entry;
	struct iovec		 iov[PDU_MAXIOV];
	size_t			 resid;
};

struct task {
	TAILQ_ENTRY(task)	 entry;
	struct pduq		 sendq;
	struct pduq		 recvq;
	void			*callarg;
	void	(*callback)(struct connection *, void *, struct pdu *);
	u_int32_t		 cmdseqnum;
	u_int32_t		 itt;
};

struct kvp {
	char	*key;
	char	*value;
};

int	parse_host(struct sockaddr_storage *, const char *, const char *);
int	socket_setblockmode(int, int);

struct initiator *initiator_init(void);
struct session *initiator_t2s(u_int);

void	session_new(struct initiator *, const char *, const char *);
void	session_task_issue(struct session *, struct task *);
void	session_schedule(struct session *);
void	session_task_login(struct connection *);
void	initiator_login(struct connection *);


void	conn_new(struct session *, const char *, const char *);
void	conn_free(struct connection *);
int	conn_task_issue(struct connection *, struct task *);
void	conn_task_schedule(struct connection *);
void	conn_pdu_write(struct connection *, struct pdu *);
void	conn_fail(struct connection *);

struct pdu *pdu_new(void);
void	*pdu_gethdr(struct pdu *, int);
void	*pdu_alloc(size_t);
int	pdu_addbuf(struct pdu *, void *, size_t);
void	*pdu_getbuf(struct pdu *, size_t *);
void	pdu_free(struct pdu *);
int	text_to_pdu(struct kvp *, struct pdu *);
struct kvp *pdu_to_text(char *, size_t);

void	pdu_free_queue(struct pduq *);
ssize_t	pdu_read(struct connection *);
ssize_t	pdu_write(struct connection *);
int	pdu_pending(struct connection *);
void	pdu_parse(struct connection *);
int	pdu_readbuf_set(struct pdu_readbuf *, size_t);
void	pdu_readbuf_free(struct pdu_readbuf *);

void	task_init(struct task *, struct session *, int, void *,
	    void (*)(struct connection *, void *, struct pdu *));
void	task_cleanup(struct task *, struct connection *c);
void	task_pdu_add(struct task *, struct pdu *);

void	vscsi_open(char *);
void	vscsi_dispatch(int, short, void *);
void	vscsi_data(unsigned long, int, void *, size_t);
void	vscsi_status(int, int, void *, size_t);
void	vscsi_event(unsigned long, u_int, u_int);
