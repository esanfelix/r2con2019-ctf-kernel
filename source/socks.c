#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/uaccess.h>

#include "socks.h"

#include <linux/spinlock.h>

/* Global device to keep track of sockets */
sock_dev_t sock_device;

#define MAX_SIZE 0x1000

/*
 * Initialize a socket with a buffer of the size given in @arg.
 */
static long socks_ioctl_init(sock_t *sock, unsigned long arg) {
    uint64_t size = arg + sizeof(sock_buf_t);
    sock_buf_t *buf = NULL;
    int err = 0;

    // Sanity check without locking the buffer.
    if (size > MAX_SIZE) {
        return -EINVAL;
    }

    // First off: lock the buffer

    spin_lock(&sock->lock);

    if (sock->state != UNINITIALIZED) {
        err = -EINVAL;
        goto out_unlock;
    }

    buf = kzalloc(size, GFP_KERNEL);
    printk(KERN_ALERT "Allocated ptr %llx\n", buf);

    if (IS_ERR_OR_NULL(buf)) {
        err = (buf ? PTR_ERR(buf) : -ENOMEM);
        goto out_unlock;
    }

    sock->buf = buf;
    sock->buf->size = size - sizeof(sock_buf_t);
    sock->buf->write_index = 0;
    sock->buf->read_index = 0;
    sock->buf->buffer = (unsigned char *)buf + sizeof(sock_buf_t); // Buffer is inline

    sock->state = INITIALIZED;

    pr_info("Initialized socket with buffer size %lx\n", sock->buf->size);


out_unlock:
    spin_unlock(&sock->lock);
    return err;
}

/*
 * Find a socket with the given name in the listening list.
 */
static sock_t *socks_find_listening_device(char *name) {
    pr_info("Searching for socket %s\n", name);
    sock_t *s = NULL;

    list_for_each_entry ( s , &sock_device.listening, listening_list ) {
        if (!strcmp(s->name, name)) {
            return s;
        }
    } 

    return NULL;
}

/*
 * Handler for the ioctl command. If successful, the 
 * socket will be listening with the provided name after its 
 * execution
 */

static long socks_ioctl_listen(sock_t *sock, unsigned long arg) {
    struct sock_name_param * __user user_param = (struct sock_name_param * __user)arg;
    struct sock_name_param local_param, *param = &local_param;
    int err = 0;

    /* Fail if copy_from_user is bad */
    if (copy_from_user(param, user_param, sizeof(*param))) {
        return -EFAULT;
    }

    /* Make sure we null-terminate the string */
    param->name[sizeof(param->name) -1] = '\0';

    pr_info("Length of name: %d\n", strlen(param->name));


    spin_lock(&sock->lock);

    /*
     * Not allowed to listen unless we are in initialized
     * state.
     */
    if (sock->state != INITIALIZED) {
        err = -EINVAL;
        goto out_unlock;
    }

    /* Make sure there is no other socket with this name */
    spin_lock(&sock_device.lock);
    if (socks_find_listening_device(param->name)) {
        err = -EINVAL;
        pr_err("There's already a socket with that name");
        spin_unlock(&sock_device.lock);
        goto out_unlock;
    }

    /* Alright, nobody else on that list. Add to the list and set to listening */
    strcpy(sock->name, param->name);
    sock->state = LISTENING;
    list_add(&sock->listening_list, &sock_device.listening);
    pr_info("Socket is now listening at %s\n", param->name);
    spin_unlock(&sock_device.lock);
    
out_unlock:
    spin_unlock(&sock->lock);
    return err;
}

static long socks_ioctl_connect(sock_t *sock, unsigned long arg) {
    struct sock_name_param * __user user_param = (struct sock_name_param * __user)arg;
    struct sock_name_param local_param, *param = &local_param;
    sock_t *peer = NULL;
    int err = 0;

    /* Fail if copy_from_user is bad */
    if (copy_from_user(param, user_param, sizeof(*param))) {
        return -EFAULT;
    }

    /* Make sure we null-terminate the string */
    param->name[63] = '\0';

    pr_info("Length of name: %d\n", strlen(param->name));

    spin_lock(&sock->lock);

    /*
     * Not allowed to connect unless we are in initialized
     * state.
     */
    if (sock->state != INITIALIZED) {
        err = -EINVAL;
        goto out_unlock;
    }

    /* Find a listening socket with that name */
    spin_lock(&sock_device.lock);
    if ( (peer = socks_find_listening_device(param->name)) == NULL) {
        pr_err("No socket with that name found");
        err = -EINVAL;
        spin_unlock(&sock_device.lock);
        goto out_unlock;
    }

    /* Remove peer from listening list */
    spin_lock(&peer->lock);
    list_del_init(&peer->listening_list);
    spin_unlock(&sock_device.lock);

    /* Connect the two sockets */
    sock->state = CONNECTED;
    sock->peer = peer;
    peer->peer = sock;
    peer->state = CONNECTED;

    pr_info("Successfully connected to %s\n", param->name);
    spin_unlock(&peer->lock);

out_unlock:
    spin_unlock(&sock->lock);
    return err;
}

/*
 * Compute the amount of data in the buffer.
 */
static size_t sock_buf_count(sock_buf_t *buf) {
    /* write_index > read_index: then write_index-read_index */
    if (buf->write_index >= buf->read_index) {
        return buf->write_index - buf->read_index;
    }

    /* If write_index is below read_index, we have available
     * from [read_index, size) + [0, write_index).
     */

    return (buf->size - buf->read_index) + buf->write_index;
}

/*
 * Compute how much space is left in the buffer.
 */
static size_t sock_buf_left(sock_buf_t *buf) {
    return buf->size - sock_buf_count(buf);
}

/*
 * Push @size bytes from userland @buffer to @buf , if enough 
 * space is left.
 */
static long socks_push(sock_buf_t *buf, void * __user buffer, size_t size) {

    /*
     * If data doesn't fit, fail.
     */
    if (sock_buf_left(buf) < size) {
        return -ENOMEM;
    }


    /* 
     * We can write up to read_index if it's bigger than write_index,
     * or up to end of buffer otherwise.
     */
    size_t max_write_index = (buf->read_index > buf->write_index) ? buf->read_index : buf->size;
    size_t copy1_size = min(size, max_write_index - buf->write_index);
    size_t prev_write_index = buf->write_index;

    if (copy_from_user(buf->buffer + buf->write_index, buffer, copy1_size)) {
        return -ENOMEM;
    }

    /* Update our write index */
    buf->write_index = (buf->write_index + copy1_size) % buf->size;

    /* More to copy, this time to beginning of buffer */
    if (size > copy1_size) {
        size_t copy_left = size - copy1_size;
        if ( (sock_buf_left(buf) < copy_left) || 
            copy_from_user(buf->buffer + buf->write_index, buffer, copy_left)) {
            /* Failed to copy, roll back */
            buf->write_index = prev_write_index;
            return -ENOMEM;            
        }

        /* Update write index again */
        buf->write_index = (buf->write_index + copy_left) % buf->size;
    }

    return size;
}

/*
 * Implement the logic to taking data out of the socket buffer.
 * Reads at most @size bytes into the userland @buffer.
 */
static long socks_pull(sock_buf_t *buf, void * __user buffer, size_t size) {

    /* Check that the buffer has some data */
    size_t count = sock_buf_count(buf);
    if ( count == 0) {
        return -EWOULDBLOCK;
    }

    /* We are going to read as much as we can, up to size */
    size_t to_read = min(count, size);

    /* Read from read_index to the end or to to_read, whatever is smaller */
    size_t copy1_size = min(to_read, buf->size - buf->read_index);
    size_t prev_read_index = buf->read_index;

    if (copy_to_user(buffer, buf->buffer + buf->read_index, copy1_size)) {
        return -ENOMEM;
    } 

    /* Update read index */
    buf->read_index = (buf->read_index + copy1_size) % buf->size;

    /* Do we still have something to read? */
    if (to_read > copy1_size) {
        /* In this case read_index must have rolled over. WARN_ON just in case */
        WARN_ON(buf->read_index != 0);

        size_t left = to_read - copy1_size;
        if (copy_to_user(buffer, buf->buffer + buf->read_index, left)) {
            /* Failed to copy, ignore the data and return ENOMEM */
            buf->read_index = prev_read_index;
            return -ENOMEM;
        }

        /* Update read index again */
        buf->read_index = (buf->read_index + copy1_size) % buf->size;

    }

    return (long)to_read;
}

/*
 * Send data to our peer.
 */

static long socks_ioctl_send(sock_t *sock, unsigned long arg) {
    struct sock_buffer_param * __user user_param = (struct sock_buffer_param * __user)arg;
    struct sock_buffer_param local_param, *param = &local_param;
    int err = 0;

    /* Fail if copy_from_user is bad */
    if (copy_from_user(param, user_param, sizeof(*param))) {
        return -EFAULT;
    }

    spin_lock(&sock->lock);

    if (sock->state != CONNECTED) {
        /* Must be connected to send! */
        err = -EINVAL;
        goto out_unlock_self;
    }

    spin_unlock(&sock->lock);

    /* Try to push the data to the peer */
    spin_lock(&sock->peer->lock);
    err = socks_push(sock->peer->buf, param->buffer, param->size);
    spin_unlock(&sock->peer->lock);

    return err;

out_unlock_self:
    spin_unlock(&sock->lock);
    return err;
}

/*
 * Receive data from the socket buffer.
 */

static long socks_ioctl_recv(sock_t *sock, unsigned long arg) {
    struct sock_buffer_param * __user user_param = (struct sock_buffer_param * __user)arg;
    struct sock_buffer_param local_param, *param = &local_param;
    int err = 0;

    /* Fail if copy_from_user is bad */
    if (copy_from_user(param, user_param, sizeof(*param))) {
        return -EFAULT;
    }

    spin_lock(&sock->lock);

    if (sock->state != CONNECTED) {
        /* Must be connected to receive! */
        err = -EINVAL;
        goto out_unlock_self;
    }

    /* Try to read from the buffer */
    err = socks_pull(sock->buf, param->buffer, param->size);

out_unlock_self:
    spin_unlock(&sock->lock);
    return err;
}

/*
 * Called when ioctl(fd, code, arg) is executed on an fd
 * created by opening /dev/socks.
 */
static long socks_ioctl (struct file *file, unsigned int code, unsigned long arg) {
    sock_t *sock = NULL;
    
    sock = (sock_t *)file->private_data;

    switch(code) {
        case IOCTL_SOCKS_INIT:
            return socks_ioctl_init(sock, arg);
        case IOCTL_SOCKS_LISTEN:
            return socks_ioctl_listen(sock, arg);
        case IOCTL_SOCKS_CONNECT:
            return socks_ioctl_connect(sock, arg);
        case IOCTL_SOCKS_SEND:
            return socks_ioctl_send(sock, arg);
        case IOCTL_SOCKS_RECV:
            return socks_ioctl_recv(sock, arg);
        default:
            return -EINVAL;
    }

    return 0;
}

/*
 * Called when open("/dev/socks", ...) is executed.
 */

static int socks_open(struct inode *inode, struct file *file)
{

    sock_t *sock = kzalloc(sizeof(*sock), GFP_KERNEL);
    
    if (!sock)
        return -ENOMEM;

    /*
     * private_data is used to keep driver-specific data. The 
     * kernel does not touch this field at all, so drivers can
     * place their data here and get it out e.g. in ioctl.
     */

    file->private_data = sock;

    /* Initialize empty listening_list head */
    INIT_LIST_HEAD(&sock->listening_list);
    pr_info("New socks successfully created!\n");

    return 0;
}

static int socks_close(struct inode *inodep, struct file *filp)
{
    sock_t *sock =  (sock_t *)filp->private_data;

    spin_lock(&sock->lock);

    if (sock->state == CONNECTED ) {
        /*
         * If we were connected, let's make sure we disconnect 
         * from the other end now.
         */

        sock_t *peer = sock->peer;
        sock->peer = NULL;

        spin_lock(&peer->lock);
        peer->peer = NULL;

        /* Back to initialized for this peer */
        peer->state = INITIALIZED;
        /* Ignore any stale data */
        peer->buf->write_index = 0;
        peer->buf->read_index = 0;

        spin_unlock(&peer->lock);

    } else if (sock->state == LISTENING) {
        /*
         * If we were listening, remove from the listening list.
         */ 

        spin_lock(&sock_device.lock);
        list_del_init(&sock->listening_list);
        spin_unlock(&sock_device.lock);
    }

    if (sock->state != UNINITIALIZED) {

        /*
         * Since we were initialized, we must have a buffer.
         * Free it.
         */

        kfree(sock->buf);
    }

    spin_unlock(&sock->lock);

    /* Finally done, free our sock */
    kfree(sock);

    return 0;
}

static const struct file_operations socks_fops = {
    .owner			= THIS_MODULE,
    .open			= socks_open,
    .release		= socks_close,
    .llseek 		= no_llseek,
    .unlocked_ioctl = socks_ioctl,
};

struct miscdevice socks_device = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "socks",
    .fops = &socks_fops,
};

static int __init misc_init(void)
{
    int error;

    INIT_LIST_HEAD(&sock_device.listening);
    spin_lock_init(&sock_device.lock);

    error = misc_register(&socks_device);
    if (error) {
        pr_err("can't misc_register :(\n");
        return error;
    }

    pr_info("I'm in\n");
    return 0;
}

static void __exit misc_exit(void)
{
    misc_deregister(&socks_device);
}

module_init(misc_init)
module_exit(misc_exit)

MODULE_DESCRIPTION("Module providing IPC through socks!");
MODULE_AUTHOR("r2");
MODULE_LICENSE("GPL");