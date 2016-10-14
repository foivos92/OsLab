/*
 * Virtio Crypto Device
 *
 * Implementation of virtio-crypto qemu backend device.
 *
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr> 
 *
 */

#include <qemu/iov.h>
#include "hw/virtio/virtio-serial.h"
#include "hw/virtio/virtio-crypto.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <crypto/cryptodev.h>

static uint32_t get_features(VirtIODevice *vdev, uint32_t features)
{
	DEBUG_IN();
	return features;
}

static void get_config(VirtIODevice *vdev, uint8_t *config_data)
{
	DEBUG_IN();
}

static void set_config(VirtIODevice *vdev, const uint8_t *config_data)
{
	DEBUG_IN();
}

static void set_status(VirtIODevice *vdev, uint8_t status)
{
	DEBUG_IN();
}

static void vser_reset(VirtIODevice *vdev)
{
	DEBUG_IN();
}

static void vq_handle_output(VirtIODevice *vdev, VirtQueue *vq)
{
	VirtQueueElement elem;
	unsigned int *syscall_type;
	//char buf[256];
	int *hfd;
	DEBUG_IN();
	if (!virtqueue_pop(vq, &elem)) {
		DEBUG("No item to pop from VQ :(");
		return;
	} 

	DEBUG("I have got an item from VQ :)");

	syscall_type = elem.out_sg[0].iov_base;
	switch (*syscall_type) {
	case VIRTIO_CRYPTO_SYSCALL_TYPE_OPEN:
		DEBUG("VIRTIO_CRYPTO_SYSCALL_TYPE_OPEN");
		hfd = elem.in_sg[0].iov_base;
		*hfd = open("/dev/crypto", O_RDWR);
		if (*hfd < 0) {
			perror("open(/dev/crypto)");
			return ;
			}
		/* ?? */
		break;

	case VIRTIO_CRYPTO_SYSCALL_TYPE_CLOSE:
		DEBUG("VIRTIO_CRYPTO_SYSCALL_TYPE_CLOSE");
		hfd=elem.out_sg[1].iov_base;
		if (close(*hfd)<0){
			perror("close");
			return ;
		}
		/* ?? */
		break;

	case VIRTIO_CRYPTO_SYSCALL_TYPE_IOCTL:
		DEBUG("VIRTIO_CRYPTO_SYSCALL_TYPE_IOCTL");
		/* ?? */
		unsigned int *cmd;
		int *ret, *sess_id;
		unsigned char *output_msg = elem.out_sg[4].iov_base;
		unsigned char *input_msg = elem.in_sg[0].iov_base;
		memcpy(input_msg, "Host: Welcome to the virtio World!", 35);
		printf("Guest says: %s\n", output_msg);
		printf("We say: %s\n", input_msg);
		cmd = elem.out_sg[2].iov_base;
		ret = elem.in_sg[1].iov_base;
		
		//CIOCGSESSION
		switch(*cmd){
			case CIOCGSESSION:
			
			DEBUG("CIOGSESSION BACKEND");
			hfd = elem.out_sg[1].iov_base;
			struct session_op *sess = elem.in_sg[1].iov_base;
			//sess->cipher=CRYPTO_AES_CBC;
			unsigned char * sesskey = elem.out_sg[3].iov_base;
			sess->key = sesskey; 
			//sess->keylen = sizeof(*sess->key);
			if (ioctl(*hfd, CIOCGSESSION, sess)) {
				*ret = -1;
				perror("Back ioctl(CIOCGSESSION)");
				}
			//RETURN VAL 
			else
			*ret = 0;
			
			break;
			
		//CIOCFSESSION
			case CIOCFSESSION:
			
			DEBUG("CIOFSESSION BACKEND");
			hfd=elem.out_sg[1].iov_base;
			sess_id=elem.out_sg[3].iov_base;
			if (ioctl(*hfd, CIOCFSESSION, sess_id)) {
				perror("Back ioctl(CIOCFSESSION)");
				*ret = -1;
				}
			//RETURN VAL
			else
			*ret = 0;
			
			break;
			
		//CIOCCRYPT
			case CIOCCRYPT:
			
			DEBUG("CIOCRYPT BACKEND");
			hfd=elem.out_sg[1].iov_base;
			struct crypt_op * cryp = elem.out_sg[3].iov_base;
			unsigned char * src = elem.out_sg[5].iov_base;
			unsigned char * iv = elem.out_sg[6].iov_base;
			unsigned char * dst = elem.in_sg[2].iov_base;
			cryp->src = src;
			cryp->iv = iv;
			cryp->dst = dst;

			
			if (ioctl(*hfd, CIOCCRYPT, cryp)) {
				perror("Back ioctl(CIOCCRYPT)");
				*ret = -1;
				}
			//RETURN VAL
			else
			*ret = 0;
			 
			break;
			
		default: 
		DEBUG("Unknown ioctl cmd");
		break;
	}
	
	break;
	
	default:
		DEBUG("Unknown syscall_type");
		break;
	}
	virtqueue_push(vq, &elem, 0);
	virtio_notify(vdev, vq);
}

static void virtio_crypto_realize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);

	DEBUG_IN();

    virtio_init(vdev, "virtio-crypto", 13, 0);
	virtio_add_queue(vdev, 128, vq_handle_output);
}

static void virtio_crypto_unrealize(DeviceState *dev, Error **errp)
{
	DEBUG_IN();
}

static Property virtio_crypto_properties[] = {
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_crypto_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *k = VIRTIO_DEVICE_CLASS(klass);

	DEBUG_IN();
    dc->props = virtio_crypto_properties;
    set_bit(DEVICE_CATEGORY_INPUT, dc->categories);

    k->realize = virtio_crypto_realize;
    k->unrealize = virtio_crypto_unrealize;
    k->get_features = get_features;
    k->get_config = get_config;
    k->set_config = set_config;
    k->set_status = set_status;
    k->reset = vser_reset;
}

static const TypeInfo virtio_crypto_info = {
    .name          = TYPE_VIRTIO_CRYPTO,
    .parent        = TYPE_VIRTIO_DEVICE,
    .instance_size = sizeof(VirtCrypto),
    .class_init    = virtio_crypto_class_init,
};

static void virtio_crypto_register_types(void)
{
    type_register_static(&virtio_crypto_info);
}

type_init(virtio_crypto_register_types)
