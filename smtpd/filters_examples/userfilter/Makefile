#	$OpenBSD: Makefile,v 1.12 2011/12/13 23:00:52 eric Exp $

.PATH:		${.CURDIR}/../..

PROG=		filter_user
BINOWN=		root

BINMODE?=555

MAN=
BINDIR=	/usr/libexec/smtpd

CFLAGS+=	-g3 -ggdb -I${.CURDIR}/../..
CFLAGS+=	-Wall -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=	-Wmissing-declarations
CFLAGS+=	-Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=	-Wsign-compare -Wbounded
CFLAGS+=	-DNO_IO

SRCS=		filter_user.c log.c util.c

LDADD+=         -levent -lutil -lsqlite3 ${.CURDIR}/../../libsmtpdfilter/obj/libsmtpdfilter.a
DPADD+=         ${LIBEVENT} ${LIBUTIL}
#DPADD+= ${.CURDIR}/../libsmtpdfilter/libsmtpdfilter.a

.include <bsd.prog.mk>
