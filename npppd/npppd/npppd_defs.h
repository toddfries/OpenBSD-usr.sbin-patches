/*-
 * Copyright (c) 2009 Internet Initiative Japan Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#ifndef NPPPD_DEFS_H
#define NPPPD_DEFS_H 1

#ifdef  _SEIL_EXT_
#include <seil/features.h>

#define	NPPPD_DEFAULT_MAX_PPP		MAX_NUMBER_OF_PPPAC_SESSION
#define	DEFAULT_NPPPD_CTL_MAX_MSGSZ				\
	    (NPPPD_DEFAULT_MAX_PPP*sizeof(struct npppd_who)	\
	    + sizeof(struct npppd_who_list) + 256)
#endif

#define NPPPD_MAX_POOLED_ADDRS		8192
#define NPPPD_USER_HASH_SIZ		1777
#define	NPPPD_GENERIC_NAME_LEN		32
#ifndef	LOG_NPPPD
#define	LOG_NPPPD			LOG_LOCAL1
#endif

#ifndef NPPPD_MAX_SERVERS
/** RADIUS�����Фο� */
#define NPPPD_MAX_SERVERS			8
#endif

#ifndef	NPPPD_TIMER_TICK_IVAL 
#define	NPPPD_TIMER_TICK_IVAL 			4
#endif

/** ǧ�ڥ��ཪλ�������Υ��󥿡��Х����(sec) */
#define NPPPD_AUTH_REALM_FINALIZER_INTERVAL		300

#ifndef	NPPPD_MAX_IPCP_CONFIG
/** IPCP����ο� */
#define	NPPPD_MAX_IPCP_CONFIG			1
#endif

#ifndef	NPPPD_MAX_IFACE
/** PPP���󥤥󥿥ե�����(tun �� pppac) �ο� */
#define	NPPPD_MAX_IFACE				1
#endif

#ifndef	NPPPD_MAX_POOL
/** �ס���ο� */
#define	NPPPD_MAX_POOL				1
#endif

#ifndef	NPPPD_MAX_PPTP
/** ��������ǧ�ڥ���ο� */
#define	NPPPD_MAX_PPTP				2
#endif

#ifndef	NPPPD_DEFAULT_AUTH_LOCAL_RELOADABLE
#define	NPPPD_DEFAULT_AUTH_LOCAL_RELOADABLE	0
#endif

/** Ʊ��桼������³�Ǥ������� PPP���å������Υǥե���� */
#define	NPPPD_DEFAULT_USER_MAX_PPP	3

#ifndef	NPPPD_DEFAULT_MAX_PPP
/** Ʊ������³�Ǥ������� PPP���å������Υǥե���� */
#define	NPPPD_DEFAULT_MAX_PPP		8192
#endif

#define	NPPPD_UID			-1	/* �ä˻��ꤷ�ʤ� */
#ifndef	NPPPD_GID			
/** npppd �¹Ի��Υ��롼��ID��*/
#define	NPPPD_GID			0
#endif

#ifndef	LOOPBACK_IFNAME
#define	LOOPBACK_IFNAME			"lo0"
#endif

#ifndef	NPPPD_DEFAULT_IP_ASSIGN_USER_SELECT
#define	NPPPD_DEFAULT_IP_ASSIGN_USER_SELECT	1
#endif
#ifndef	NPPPD_DEFAULT_IP_ASSIGN_FIXED
#define	NPPPD_DEFAULT_IP_ASSIGN_FIXED		1
#endif
#ifndef	NPPPD_DEFAULT_IP_ASSIGN_RADIUS
#define	NPPPD_DEFAULT_IP_ASSIGN_RADIUS		0
#endif

/** rtev_write() ��Ȥ� */
#define NPPPD_USE_RTEV_WRITE			1

#ifndef DEFAULT_RTSOCK_EVENT_DELAY
/** Routing �����åȥ��٥�Ȥ�����Ƥ��顢�����򳫻Ϥ���ޤǤ��Ԥ�����(��)*/
#define	DEFAULT_RTSOCK_EVENT_DELAY		5
#endif
#ifndef DEFAULT_RTSOCK_SEND_NPKTS
/** Routing �����åȤ˽񤭹���ݤ˰��٤˽񤯥ѥ��åȿ�*/
#define	DEFAULT_RTSOCK_SEND_NPKTS		16
#endif
#ifndef DEFAULT_RTSOCK_SEND_WAIT_MILLISEC
/** Routing �����åȤؤ�Ϣ³�񤭹��ߤǴֳ֤���������(�ߥ���) */
#define	DEFAULT_RTSOCK_SEND_WAIT_MILLISEC	0
#endif

#ifndef	countof
#define	countof(x)	(sizeof(x) / sizeof((x)[0]))
#endif

#endif