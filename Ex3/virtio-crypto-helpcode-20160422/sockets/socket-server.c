#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <crypto/cryptodev.h>

#include "socket-common.h"
#define KEY_SIZE	16
#define BLOCK_SIZE	16
/* Convert a buffer to upercase */
void toupper_buf(char *buf, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		buf[i] = toupper(buf[i]);
}

/* Insist until all of the data has been read */
ssize_t insist_read(int fd, void *buf, size_t cnt)
{
        ssize_t ret;
        size_t orig_cnt = cnt;

        while (cnt > 0) {
                ret = read(fd, buf, cnt);
                if (ret == 0) {
                	printf("Remote peer went away\n");
                	return 0;
                }
                if (ret < 0) {
                	perror("read from remote peer failed");
                        return ret;
                }
                buf += ret;
                cnt -= ret;
        }

        return orig_cnt;
}

/* Insist until all of the data has been written */
ssize_t insist_write(int fd, const void *buf, size_t cnt)
{
	ssize_t ret;
	size_t orig_cnt = cnt;
	
	while (cnt > 0) {
	        ret = write(fd, buf, cnt);
	        if (ret < 0)
	                return ret;
	        buf += ret;
	        cnt -= ret;
	}

	return orig_cnt;
}

int main(void)
{
	char buf[256],temp[256],key[KEY_SIZE+1],iv[BLOCK_SIZE+1];
	char addrstr[INET_ADDRSTRLEN];
	int fd, sd, newsd;
	socklen_t len;
	fd_set readfd;
	struct sockaddr_in sa;
	struct session_op sess;
	struct crypt_op cryp;
	
	memset(&sess, 0, sizeof(sess));
	memset(&cryp, 0, sizeof(cryp));
	
	/* Make sure a broken connection doesn't kill us */
	signal(SIGPIPE, SIG_IGN);

	/* Create TCP/IP socket, used as main chat channel */
	if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		exit(1);
	}
	printf("Created TCP socket\n");

	/* Bind to a well-known port */
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(TCP_PORT);
	sa.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(sd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("bind");
		exit(1);
	}
	printf("Bound TCP socket to port %d\n", TCP_PORT);

	/* Listen for incoming connections */
	if (listen(sd, 1) < 0) {
		perror("listen");
		exit(1);
	}
	
	fd = open("/dev/crypto", O_RDWR);
	if (fd < 0) {
		perror("open(/dev/crypto)");
		return 1;
	}
	
	strcpy(iv,IV);
	strcpy(key,KEY);
	
	/*
	 * Get crypto session for AES128
	 */
	sess.cipher = CRYPTO_AES_CBC;
	sess.keylen = KEY_SIZE;
	sess.key = key;

	if (ioctl(fd, CIOCGSESSION, &sess)) {
		perror("ioctl(CIOCGSESSION)");
		return 1;
	}
	
	cryp.ses = sess.ses;
	cryp.iv = iv;
	cryp.src = (unsigned char*)buf;
	cryp.dst = (unsigned char*)temp;
	cryp.len = sizeof(buf);
	/* Loop forever, accept()ing connections */
	for (;;) {
		printf("Waiting for an incoming connection...\n");

		/* Accept an incoming connection */
		len = sizeof(struct sockaddr_in);
		if ((newsd = accept(sd, (struct sockaddr *)&sa, &len)) < 0) {
			perror("accept");
			exit(1);
		}
		if (!inet_ntop(AF_INET, &sa.sin_addr, addrstr, sizeof(addrstr))) {
			perror("could not format IP address");
			exit(1);
		}
		printf("%d\n",newsd);
		printf("Incoming connection from %s:%d\n",
			addrstr, ntohs(sa.sin_port));
		FD_ZERO(&readfd);
		int max=0,array[2],n=0,i,ret;
		array[0]=newsd;
		array[1]=0;

		/* We break out of the loop when the remote peer goes away */
		for (;;) {
	for (i=0; i<2; i++){
		FD_SET(array[i],&readfd);
		if (array[i]>max){
			max=array[i];
			}
		}
			ret=select(max+1,&readfd,NULL,NULL,NULL);
			if (ret==-1){
				perror("select error");
				}
			else{
				for (i=0;i<2;i++){
					//printf("IFSSET SERVER i:%d\n",i);
					if (FD_ISSET(array[i],&readfd)){
						if(i==0){
							memset(temp, 0, sizeof(temp));

							if (insist_read(newsd, buf, 256) != 256) break;
							cryp.src = buf;
							cryp.dst = temp;
							cryp.op = COP_DECRYPT;
			
							if (ioctl(fd, CIOCCRYPT, &cryp)) {
								perror("ioctl(CIOCCRYPT)");
								return 1;
							}
							toupper_buf(temp,sizeof(buf));
							printf("Client Says: %s\n",temp);
							//printf("You: ");

							if ( strcmp(buf,"/exit\n")==0 ) {
								if (ioctl(fd, CIOCFSESSION, &sess.ses)) {
									perror("ioctl(CIOCFSESSION)");
									return 1;
								}
								if (close(fd) < 0) {
									perror("close(fd)");
									return 1;
								}
								if (close(newsd) < 0)
									perror("close");
								if (close(sd) < 0)
									perror("close");
								return 0;
								}
							}
						else{
							memset(temp, 0, sizeof(temp));
							memset(buf, 0, sizeof(buf));
							n=read(0, buf, 256);
							if (n < 0) {
								perror("read");
								exit(1);
								}
							if ( strcmp(buf,"/exit\n")==0 ) {
								if (ioctl(fd, CIOCFSESSION, &sess.ses)) {
									perror("ioctl(CIOCFSESSION)");
									return 1;
									}
								if (close(fd) < 0) {
									perror("close(fd)");	
									return 1;
									}
								if (close(sd) < 0){
									perror("close");
									return 0;
									}
								return 0;
								}
							cryp.src = buf;
							cryp.dst = temp;
							cryp.op = COP_ENCRYPT;
			
							if (ioctl(fd, CIOCCRYPT, &cryp)) {
								perror("ioctl(CIOCCRYPT)");
								return 1;
							}
			
							if (insist_write(newsd, temp, 256) != 256) {
								printf("write to remote peer failed\n");
								break;
								}
							}
						}
					}
					}
			}
						
		}
		/* Make sure we don't leak open files */
						if (close(newsd) < 0)
							perror("close");

	/* This will never happen */
	return 1;
}
