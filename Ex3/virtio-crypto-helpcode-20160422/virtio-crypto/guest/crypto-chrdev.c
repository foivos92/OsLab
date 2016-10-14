/*
 * crypto-chrdev.c
 *
 * Implementation of character devices
 * for virtio-crypto device 
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr>
 *
 */
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/wait.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>

#include "crypto.h"
#include "crypto-chrdev.h"
#include "debug.h"

#include "cryptodev.h"

/*
 * Global data
 */
struct cdev crypto_chrdev_cdev;

/**
 * Given the minor number of the inode return the crypto device 
 * that owns that number.
 **/
static struct crypto_device *get_crypto_dev_by_minor(unsigned int minor)
{
	struct crypto_device *crdev;
	unsigned long flags;

	debug("Entering");

	spin_lock_irqsave(&crdrvdata.lock, flags);
	list_for_each_entry(crdev, &crdrvdata.devs, list) {
		if (crdev->minor == minor)
			goto out;
	}
	crdev = NULL;

out:
	spin_unlock_irqrestore(&crdrvdata.lock, flags);

	debug("Leaving");
	return crdev;
}

/*************************************
 * Implementation of file operations
 * for the Crypto character device
 *************************************/

static int crypto_chrdev_open(struct inode *inode, struct file *filp)
{
	unsigned int num_out = 0;
	unsigned int num_in = 0;
	int ret = 0;
	int err;
	unsigned int len;
	struct crypto_open_file *crof;
	struct crypto_device *crdev;
	unsigned int syscall_type = VIRTIO_CRYPTO_SYSCALL_OPEN;
	int host_fd = -1;
	struct scatterlist syscall_type_sg, host_fd_sg, *sgs[2];
	debug("Entering");

	ret = -ENODEV;
	if ((ret = nonseekable_open(inode, filp)) < 0)
		goto fail;

	/* Associate this open file with the relevant crypto device. */
	crdev = get_crypto_dev_by_minor(iminor(inode));
	if (!crdev) {
		debug("Could not find crypto device with %u minor", 
		      iminor(inode));
		ret = -ENODEV;
		goto fail;
	}

	crof = kzalloc(sizeof(*crof), GFP_KERNEL);
	if (!crof) {
		ret = -ENOMEM;
		goto fail;
	}
	crof->crdev = crdev;
	crof->host_fd = -1;
	filp->private_data = crof;

	/**
	 * We need two sg lists, one for syscall_type and one to get the 
	 * file descriptor from the host.
	 **/
	/* ?? */
	
	//syscall
	sg_init_one(&syscall_type_sg, &syscall_type, sizeof(syscall_type));
	sgs[num_out++] = &syscall_type_sg;
	
	//host_fd
	sg_init_one(&host_fd_sg,&host_fd, sizeof(host_fd));
	sgs[num_out + num_in++] = &host_fd_sg;
	
	virtqueue_add_sgs(crdev->vq,sgs,num_out,num_in,&syscall_type_sg,GFP_ATOMIC);
	virtqueue_kick(crdev->vq);
	
	/**
	 * Wait for the host to process our data.
	 **/
	/* ?? */
	
	while(virtqueue_get_buf(crdev->vq,&len) == NULL);

	/* If host failed to open() return -ENODEV. */
	/* ?? */
	if ((crof->host_fd=host_fd)<=0){
		ret= -ENODEV;
		goto fail;
		}	

fail:
	debug("Leaving");
	return ret;
}

static int crypto_chrdev_release(struct inode *inode, struct file *filp)
{
	int ret = 0;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	unsigned int syscall_type = VIRTIO_CRYPTO_SYSCALL_CLOSE, len;
	struct scatterlist syscall_type_sg, host_fd_sg, ret_sg, *sgs[3];
	debug("Entering");

	/**
	 * Send data to the host.
	 **/
	/* ?? */
	//syscall
	sg_init_one(&syscall_type_sg, &syscall_type, sizeof(syscall_type));
	sgs[0] = &syscall_type_sg;
	//host_fd
	sg_init_one(&host_fd_sg, &crof->host_fd, sizeof(crof->host_fd));
	sgs[1] = &host_fd_sg;
	//ret
	sg_init_one(&ret_sg,&ret,sizeof(ret));
	sgs[2] = &ret_sg;
	virtqueue_add_sgs(crdev->vq,sgs,2,1,&syscall_type_sg,GFP_ATOMIC);
	virtqueue_kick(crdev->vq);
	/**
	 * Wait for the host to process our data.
	 **/
	/* ?? */
	while(virtqueue_get_buf(crdev->vq,&len) == NULL);
	
	kfree(crof);
	debug("Leaving");
	return ret;

}

static long crypto_chrdev_ioctl(struct file *filp, unsigned int cmd, 
                                unsigned long arg)
{
	long ret = 0,host_ret;
	int err;
	uint32_t id;
	struct session_op sess;
	struct crypt_op cryp, temp1;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	struct virtqueue *vq = crdev->vq;
	struct scatterlist syscall_type_sg, output_msg_sg, input_msg_sg, cmd_sg, session_sg, host_fd_sg, ret_sg, sess_id_sg, cryp_src_sg, cryp_dst_sg, cryp_iv_sg, cryp_op_sg, seskey_sg, 
	                   *sgs[13];
#define MSG_LEN 100
	unsigned char output_msg[MSG_LEN], input_msg[MSG_LEN], *seskey, *src, *dst, *iv, *temp;
	unsigned int num_out, num_in,
	             syscall_type = VIRTIO_CRYPTO_SYSCALL_IOCTL,
	             len;
	unsigned long flags;

	debug("Entering ");

	num_out = 0;
	num_in = 0;
	seskey = NULL;
	src = NULL;
	dst = NULL;
	iv = NULL;
	temp = NULL;
	/**
	 *  These are common to all ioctl commands.
	 **/
	 
	 //syscall
	sg_init_one(&syscall_type_sg, &syscall_type, sizeof(syscall_type));
	sgs[num_out++] = &syscall_type_sg;
	
	//host
		sg_init_one(&host_fd_sg, &crof->host_fd,sizeof(crof->host_fd));
		sgs[num_out++] = &host_fd_sg;
	/* ?? */
	/**
	 *  Add all the cmd specific sg lists.
	 **/
	switch (cmd) {
	case CIOCGSESSION:
		debug("CIOCGSESSION");
		memcpy(output_msg, "Hello HOST from ioctl CIOCGSESSION.", 36);
		input_msg[0] = '\0';
			
		//cmd
		sg_init_one(&cmd_sg, &cmd, sizeof(cmd));
		sgs[num_out++] = &cmd_sg;
		
		//sess key
		err = copy_from_user(&sess, (struct session_op*)arg, sizeof(struct session_op));
		if(err){
			debug("Copy from user 1");
			ret = -1;
			goto fail;
		}
		seskey = kzalloc(sess.keylen*sizeof(char), GFP_KERNEL);
		if (!seskey) {
			ret = -ENOMEM;
		goto fail;
		}
		if(copy_from_user(seskey, sess.key, sizeof(char)*sess.keylen)){
			debug("Copy from user 2");
			ret = -1;
			goto fail;
		} 
		sg_init_one(&seskey_sg, seskey, sizeof(char)*sess.keylen);
		sgs[num_out++] = &seskey_sg;
		
		//msg out
		sg_init_one(&output_msg_sg, output_msg, MSG_LEN);
		sgs[num_out++] = &output_msg_sg;
		
		//msg in
		sg_init_one(&input_msg_sg, input_msg, MSG_LEN);
		sgs[num_out + num_in++] = &input_msg_sg;
		
		//sess op
		sg_init_one(&session_sg, &sess, sizeof(sess));
		sgs[num_out + num_in++] = &session_sg;
		
		//host ret
		sg_init_one(&ret_sg, &host_ret, sizeof(host_ret));
		sgs[num_out + num_in++] = &ret_sg;
		

		break;

	case CIOCFSESSION:
		debug("CIOCFSESSION");
		memcpy(output_msg, "Hello HOST from ioctl CIOCFSESSION.", 36);
		input_msg[0] = '\0';
		
		//cmd
		sg_init_one(&cmd_sg, &cmd, sizeof(cmd));
		sgs[num_out++] = &cmd_sg;
		
		//sess id
		if(copy_from_user(&id,(uint32_t*)arg,sizeof(id))){
			debug("Copy from user 1");
			ret = -1;
			goto fail;
		}
		sg_init_one(&sess_id_sg, &id, sizeof(id));
		sgs[num_out++] = &sess_id_sg;
		//msg out
		sg_init_one(&output_msg_sg, output_msg, MSG_LEN);
		sgs[num_out++] = &output_msg_sg;
		
		//msg in
		sg_init_one(&input_msg_sg, input_msg, MSG_LEN);
		sgs[num_out + num_in++] = &input_msg_sg;
		
		//host ret
		sg_init_one(&ret_sg, &host_ret, sizeof(int));
		sgs[num_out + num_in++] = &ret_sg;

		break;

	case CIOCCRYPT:
		debug("CIOCCRYPT");
		memcpy(output_msg, "Hello HOST from ioctl CIOCCRYPT.", 33);
		input_msg[0] = '\0';
		
		//cmd
		sg_init_one(&cmd_sg, &cmd, sizeof(cmd));
		sgs[num_out++] = &cmd_sg;
		
		//crypt op
		if(copy_from_user(&cryp , (struct crypt_op*)arg, sizeof( struct crypt_op))){
			debug("Copy from user 1");
			ret = -1;
			goto fail;
		}
		sg_init_one(&cryp_op_sg, &cryp, sizeof(cryp));
		sgs[num_out++] = &cryp_op_sg;
		
		//out msg
		sg_init_one(&output_msg_sg, output_msg, MSG_LEN);
		sgs[num_out++] = &output_msg_sg;
		
		//src
		src = kzalloc(cryp.len*sizeof(char), GFP_KERNEL);
		if (!src) {
			ret = -ENOMEM;
			goto fail;
		}
		if(copy_from_user(src, cryp.src, cryp.len*sizeof(char))){
			debug("Copy from user 2");
			ret = -1;
			goto fail;
		}
		sg_init_one(&cryp_src_sg, src, cryp.len*sizeof(char));
		sgs[num_out++] = &cryp_src_sg;
		
		//iv
		iv = kzalloc(16*sizeof(char), GFP_KERNEL);
		if (!iv) {
			ret = -ENOMEM;
			goto fail;
		}
		if(copy_from_user(iv, cryp.iv, 16*sizeof(char))){
			debug("Copy from user 3");
			ret = -1;
			goto fail;
		}
		sg_init_one(&cryp_iv_sg, iv, cryp.len*sizeof(char));
		sgs[num_out++] = &cryp_iv_sg;
		
		//inmsg
		sg_init_one(&input_msg_sg, input_msg, MSG_LEN);
		sgs[num_out + num_in++] = &input_msg_sg;
		
		//host ret
		sg_init_one(&ret_sg, &host_ret, sizeof(int));
		sgs[num_out + num_in++] = &ret_sg;
		
		//dst
		temp = cryp.dst;
		dst = kzalloc(cryp.len*sizeof(char), GFP_KERNEL);
		if (!dst) {
			ret = -ENOMEM;
			goto fail;
		}
		sg_init_one(&cryp_dst_sg, dst, cryp.len*sizeof(char));
		sgs[num_out + num_in++] = &cryp_dst_sg;
		
		break;

	default:
		debug("Unsupported ioctl command");

		break;
	}


	/**
	 * Wait for the host to process our data.
	 **/
	/* ?? */
	/* ?? Lock ?? */
	spin_lock_irqsave(&crdev->lock, flags);
	
	err = virtqueue_add_sgs(crdev->vq, sgs, num_out, num_in, 
	                        &syscall_type_sg, GFP_ATOMIC);
	virtqueue_kick(crdev->vq);
	while (virtqueue_get_buf(crdev->vq, &len) == NULL)
		/* do nothing */;
	spin_unlock_irqrestore(&crdev->lock, flags);
	
	switch(cmd){
	case CIOCGSESSION:
		debug("CIOCGSESSION RET");
		if(copy_to_user((struct session_op*)arg, &sess,sizeof(struct session_op))){
			debug("Copy to user");
			ret = -1;
			goto fail;
		}

		break;
		
	case CIOCFSESSION:
		debug("CIOCFSESSION RET");
	
		break;
		
	case CIOCCRYPT:
		debug("CIOCCRYPT RET");
		if(copy_to_user(temp, dst, cryp.len*sizeof(char))){
			debug("Copy to user");
			ret = -1;
			goto fail;
		}
		
		break;
		
	}
	
	debug("We said: '%s'", output_msg);
	debug("Host answered: '%s'", input_msg);
fail:
	debug("Leaving");
	return ret;
}

static ssize_t crypto_chrdev_read(struct file *filp, char __user *usrbuf, 
                                  size_t cnt, loff_t *f_pos)
{
	debug("Entering");
	debug("Leaving");
	return -EINVAL;
}

static struct file_operations crypto_chrdev_fops = 
{
	.owner          = THIS_MODULE,
	.open           = crypto_chrdev_open,
	.release        = crypto_chrdev_release,
	.read           = crypto_chrdev_read,
	.unlocked_ioctl = crypto_chrdev_ioctl,
};

int crypto_chrdev_init(void)
{
	int ret;
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;
	
	debug("Initializing character device...");
	cdev_init(&crypto_chrdev_cdev, &crypto_chrdev_fops);
	crypto_chrdev_cdev.owner = THIS_MODULE;
	
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	ret = register_chrdev_region(dev_no, crypto_minor_cnt, "crypto_devs");
	if (ret < 0) {
		debug("failed to register region, ret = %d", ret);
		goto out;
	}
	ret = cdev_add(&crypto_chrdev_cdev, dev_no, crypto_minor_cnt);
	if (ret < 0) {
		debug("failed to add character device");
		goto out_with_chrdev_region;
	}

	debug("Completed successfully");
	return 0;

out_with_chrdev_region:
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
out:
	return ret;
}

void crypto_chrdev_destroy(void)
{
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;

	debug("entering");
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	cdev_del(&crypto_chrdev_cdev);
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
	debug("leaving");
}
