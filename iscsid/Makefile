#	$OpenBSD$

PROG=	iscsid
SRCS=	connection.c initiator.c iscsid.c log.c pdu.c vscsi.c

#MAN=	iscsid.8

DEBUG=-g
CFLAGS+= -Wall
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+= -Wsign-compare
LDADD+= -levent
DPADD+= ${LIBEVENT}

.include <bsd.prog.mk>
