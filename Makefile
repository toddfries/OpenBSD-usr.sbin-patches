#	$OpenBSD: Makefile,v 1.161 2012/03/05 11:15:41 dlg Exp $

.include <bsd.own.mk>

SUBDIR=	ac accton acpidump adduser amd apm apmd arp \
	authpf bgpctl bgpd bind chroot config cron crunchgen dev_mkdb \
	dhcpd dhcrelay dvmrpctl dvmrpd edquota eeprom faithd fdformat \
	ftp-proxy fw_update gpioctl hostapd hotplugd httpd ifstated ikectl \
	inetd iostat iscsictl iscsid \
	kgmon kvm_mkdb ldapd ldapctl ldpd ldpctl lpr mailwrapper map-mbone \
	memconfig mksuncd mopd mrinfo mrouted mtrace mtree ndp netgroup_mkdb \
	nginx nsd ntpd openssl ospfctl ospfd ospf6d ospf6ctl pcidump pkg_add \
	popa3d portmap ppp pppd pppoe procmap pstat pwd_mkdb quot quotaon \
	rarpd rbootd rdate relayctl relayd repquota rip6query ripctl ripd \
	rmt route6d rpc.bootparamd rpc.lockd rpc.statd rtadvd rtsold rwhod \
	sa sasyncd sensorsd sliplogin slstats smtpd snmpctl snmpd spamdb \
	wsconscfg wsfontload wsmoused zdump zic ztsscale
	spray syslogc syslogd sysmerge tcpdrop tcpdump tftpd tokenadm \
	tokeninit traceroute traceroute6 trpt unbound usbdevs user vipw \
	watchdogd wsconscfg wsfontload wsmoused zdump zic ztsscale

.if (${AFS:L} == "yes")
SUBDIR+=afs
.endif

.if (${YP:L} == "yes")
SUBDIR+=ypbind ypldap yppoll ypset ypserv
.endif

.include <bsd.subdir.mk>

