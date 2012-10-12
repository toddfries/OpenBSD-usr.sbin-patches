#ifndef __DNS_H_
#define __DNS_H_

enum dns_status {
	DNS_OK = 0,
	DNS_RETRY,
	DNS_EINVAL,
	DNS_ENONAME,
	DNS_ENOTFOUND,
};

struct dns {
	uint64_t		 id;
	char			 host[MAXHOSTNAMELEN];
	char			 backup[MAXHOSTNAMELEN];
	int			 port;
	int			 error;
	int			 type;
	struct imsgev		*asker;
	struct sockaddr_storage	 ss;
};

#endif /* __DNS_H_ */
