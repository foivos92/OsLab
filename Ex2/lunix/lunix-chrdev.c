/*
 * lunix-chrdev.c
 *
 * Implementation of character devices
 * for Lunix:TNG
 *
 * < foivos^2 >
 *
 */

#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mmzone.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>

#include "lunix.h"
#include "lunix-chrdev.h"
#include "lunix-lookup.h"

/*
 * Global data
 */
struct cdev lunix_chrdev_cdev;

/*
 * Just a quick [unlocked] check to see if the cached
 * chrdev state needs to be updated from sensor measurements.
 */
static int lunix_chrdev_state_needs_refresh(struct lunix_chrdev_state_struct *state)
{
	struct lunix_sensor_struct *sensor;
	
	WARN_ON ( !(sensor = state->sensor));
	/* ? */
	if (sensor->msr_data[0]->last_update != state->buf_timestamp)
		return 1;
	/* The following return is bogus, just for the stub to compile*/
	return 0; /* ? */
}

/*
 * Updates the cached state of a character device
 * based on sensor data. Must be called with the
 * character device state lock held.
 */
static int lunix_chrdev_state_update(struct lunix_chrdev_state_struct *state)
{
	//struct lunix_sensor_struct *sensor;
	unsigned long flags;
	uint32_t measures,timestamp;
	 
	debug("updating\n");
	
	/*
	 * Grab the raw data quickly, hold the
	 * spinlock for as little as possible.
	 */
	spin_lock_irqsave(&state->sensor->lock,flags);
	/* ? */
	/* Why use spinlocks? See LDD3, p. 119 */

	/*
	 * Any new data available?
	 */
	/* ? */
	
	measures = state->sensor->msr_data[state->type]->values[0];
	timestamp = state->sensor->msr_data[state->type]->last_update;
	spin_unlock_irqrestore(&state->sensor->lock,flags);
	if(timestamp==state->buf_timestamp)
		return -EAGAIN;
	/*
	 * Now we can take our time to format them,
	 * holding only the private state semaphore
	 */
	
	/* ? */
	//down(&state->lock);
	switch (state->type){
		case BATT: measures=lookup_voltage[measures];
			   state->buf_data[0]='b';
			break;
		case TEMP: measures=lookup_temperature[measures];
			   state->buf_data[0]='t';
			break;
		case LIGHT: measures=lookup_light[measures];
			    state->buf_data[0]='l';
	}
 	debug("measures %d\n",measures);
	state->buf_data[1]='0'+measures/10000;
	measures=measures%10000;
	state->buf_data[2]='0'+measures/1000;
	measures=measures%1000;
	state->buf_data[3]='.';
	state->buf_data[4]='0'+measures/100;
	measures=measures%100;
	state->buf_data[5]='0'+measures/10;
	measures=measures%10;
	state->buf_data[6]='0'+measures;
	state->buf_data[7]='\n';
	state->buf_lim=8;
	state->buf_timestamp=timestamp;
	//up(&state->lock);
	debug("leaving\n");
	return 0;
}

/*************************************
 * Implementation of file operations
 * for the Lunix character device
 *************************************/

static int lunix_chrdev_open(struct inode *inode, struct file *filp)
{
	/* Declarations */
	/* ? */
	dev_t minor;
	int ret;
	int type;
	struct lunix_chrdev_state_struct *dev=NULL;
	debug("entering\n");
	ret = -ENODEV;
	if ((ret = nonseekable_open(inode, filp)) < 0)
		goto out;

	/*
	 * Associate this open file with the relevant sensor based on
	 * the minor number of the device node [/dev/sensor<NO>-<TYPE>]
	 */
	
	/* Allocate a new Lunix character device private state structure */
	/* ? */
	minor= iminor(inode);
	type=minor%8;
	dev = kmalloc(sizeof(struct lunix_chrdev_state_struct ),GFP_KERNEL);
	if (dev==NULL){
		printk(KERN_ERR "kmalloc failed");
		ret=-EFAULT;
		goto out;}
	dev->type=type;
	dev->buf_lim=0;
	dev->buf_timestamp=0;
	sema_init(&dev->lock,1);
	dev->sensor=lunix_sensors+minor/8;
	filp->private_data= dev;
	
out:
	debug("leaving, with ret = %d\n", ret);
	return ret;
}

static int lunix_chrdev_release(struct inode *inode, struct file *filp)
{	
	struct lunix_chrdev_state_struct *dev=filp->private_data;
	dev->sensor=NULL;
	kfree(filp->private_data);
	return 0;
}

static long lunix_chrdev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	/* Why? */
	return -EINVAL;
}

static ssize_t lunix_chrdev_read(struct file *filp, char __user *usrbuf, size_t cnt, loff_t *f_pos)
{
	ssize_t ret;
	
	struct lunix_sensor_struct *sensor;
	struct lunix_chrdev_state_struct *state;

	state = filp->private_data;
	WARN_ON(!state);
	sensor = state->sensor;
	WARN_ON(!sensor);
	
	
	/* Lock? */
	if(down_interruptible(&state->lock)) return -ERESTARTSYS;
	/*
	 * If the cached character device state needs to be
	 * updated by actual sensor data (i.e. we need to report
	 * on a "fresh" measurement, do so
	 */
	if (*f_pos==0){
	while (lunix_chrdev_state_update(state) == -EAGAIN) {
		up(&state->lock);
		debug("sleeping till i got data");
		if(wait_event_interruptible(sensor->wq,lunix_chrdev_state_needs_refresh(state)))
			return -ERESTARTSYS;
		if(down_interruptible(&state->lock))
			return -ERESTARTSYS;
		}
	}	/* ? */
			/* The process needs to sleep */
			/* See LDD3, page 153 for a hint */
	/* End of file */
	/* ? */
	if (*f_pos+state->buf_lim > cnt){
		state->buf_lim=cnt;
		debug("no space");
	}
	ret = (ssize_t)copy_to_user(usrbuf,state->buf_data+(*f_pos),(size_t)state->buf_lim);
	if (ret){
		up(&state->lock);
		return -EAGAIN;
	}
	*f_pos += ret;
	ret =state->buf_lim;
        
out:
	/* Unlock? */
	up(&state->lock);
	debug("RELEASE LOCK FINAL, ret = %d",ret);
	return ret;
}

static int lunix_chrdev_mmap(struct file *filp, struct vm_area_struct *vma)
{
	return -EINVAL;
}

static struct file_operations lunix_chrdev_fops = 
{
        .owner          = THIS_MODULE,
	.open           = lunix_chrdev_open,
	.release        = lunix_chrdev_release,
	.read           = lunix_chrdev_read,
	.unlocked_ioctl = lunix_chrdev_ioctl,
	.mmap           = lunix_chrdev_mmap
};

int lunix_chrdev_init(void)
{
	/*
	 * Register the character device with the kernel, asking for
	 * a range of minor numbers (number of sensors * 8 measurements / sensor)
	 * beginning with LINUX_CHRDEV_MAJOR:0
	 */
	int ret;
	dev_t dev_no;
	unsigned int lunix_minor_cnt = lunix_sensor_cnt << 3;
	
	debug("initializing character device\n");
	cdev_init(&lunix_chrdev_cdev, &lunix_chrdev_fops);
	lunix_chrdev_cdev.owner = THIS_MODULE;
	
	dev_no = MKDEV(LUNIX_CHRDEV_MAJOR, 0);
	/* ? */
	/* register_chrdev_region? */
	ret=register_chrdev_region(dev_no,lunix_minor_cnt,"foivos^2");
	if (ret < 0) {
		debug("failed to register region, ret = %d\n", ret);
		goto out;
	}	
	/* ? */
	/* cdev_add? */
	ret=cdev_add(&lunix_chrdev_cdev,dev_no,lunix_minor_cnt);
	if (ret < 0) {
		debug("failed to add character device\n");
		goto out_with_chrdev_region;
	}
	debug("completed successfully\n");
	return 0;

out_with_chrdev_region:
	unregister_chrdev_region(dev_no, lunix_minor_cnt);
out:
	return ret;
}

void lunix_chrdev_destroy(void)
{
	dev_t dev_no;
	unsigned int lunix_minor_cnt = lunix_sensor_cnt << 3;
		
	debug("entering\n");
	dev_no = MKDEV(LUNIX_CHRDEV_MAJOR, 0);
	cdev_del(&lunix_chrdev_cdev);
	unregister_chrdev_region(dev_no, lunix_minor_cnt);
	debug("leaving\n");
}
