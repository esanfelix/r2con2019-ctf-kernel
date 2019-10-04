#ifndef __SOCKS_H__

#define __SOCKS_H__

#include <linux/spinlock.h>
#include <linux/types.h>

typedef struct sock sock_t;

/* Describes the socket buffer after initialization */
typedef struct sock_buf {
	size_t size; 			/* Size of the buffer */
	unsigned char *buffer; 	/* Pointer to data */
	size_t read_index;		/* Offset of unread data inside buffer */
	size_t write_index;		/* Offset where new data will be written */
} sock_buf_t;

/* Describes a socket */
typedef struct sock {
	spinlock_t lock; 				 /* Protect all fields in the structure */
	struct list_head listening_list; /* Link for the list of listening devices */
	unsigned char name[64];			 /* The name of this socket when it's listening */
	int state;						 /* The state of the socket */
	sock_t *peer;					 /* The peer we are connected to, if any */
	sock_buf_t *buf;				 /* The sock_buf_t representing this socket's data buffer */
} sock_t;

typedef enum {
	UNINITIALIZED = 0,
	INITIALIZED = 1,
	LISTENING = 2,
	CONNECTED = 3,
} sock_state;

/* Describes the sockets device */
typedef struct sock_device {
	spinlock_t lock; 			/* Protect listening list */
	struct list_head listening; /* List of listening sockets */
} sock_dev_t;

/* Parameter for listen/connect ioctls */
struct sock_name_param {
	char name[64];
};

/* Parameter for send/recv ioctls */
struct sock_buffer_param {
	uint64_t size;
	void * __user buffer;
};

/* ioctl codes */
#define IOCTL_SOCKS_INIT			_IOWR('s', 1, uint64_t)
#define IOCTL_SOCKS_LISTEN		_IOWR('s', 2, struct sock_name_param)
#define IOCTL_SOCKS_CONNECT		_IOWR('s', 3, struct sock_name_param)
#define IOCTL_SOCKS_SEND			_IOWR('s', 4, struct sock_buffer_param)
#define IOCTL_SOCKS_RECV			_IOWR('s', 5, struct sock_buffer_param)
#define IOCTL_SOCKS_RESIZE		_IOWR('s', 6, uint64_t)



#endif
