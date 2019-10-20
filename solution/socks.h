#ifndef __SOCKS_H__

#include <stdint.h>
#include <sys/ioctl.h>

#define __SOCKS_H__

struct sock_name_param {
	char name[64];
};

struct sock_buffer_param {
	uint64_t size;
	void *buffer;
};

#define IOCTL_SOCKS_INIT			_IOWR('s', 1, uint64_t)
#define IOCTL_SOCKS_LISTEN		_IOWR('s', 2, struct sock_name_param)
#define IOCTL_SOCKS_CONNECT		_IOWR('s', 3, struct sock_name_param)
#define IOCTL_SOCKS_SEND			_IOWR('s', 4, struct sock_buffer_param)
#define IOCTL_SOCKS_RECV			_IOWR('s', 5, struct sock_buffer_param)
#define IOCTL_SOCKS_RESIZE		_IOWR('s', 6, uint64_t)

#endif