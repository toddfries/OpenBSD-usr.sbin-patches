#include <sys/types.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <imsg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "smtpd.h"
#include "log.h"


int queue_encrypt_file(int fdin, int fdout)
{
	return (1);
}

int queue_decrypt_file(int fd)
{
	return (1);
}

size_t queue_encrypt_buffer(char *ib, size_t iblen, char *ob, size_t oblen)
{
	return (1);
}

size_t queue_decrypt_buffer(char *ib, size_t iblen, char *ob, size_t oblen)
{
	return (1);
}
