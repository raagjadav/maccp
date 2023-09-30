/*
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2, as
 *  published by the Free Software Foundation.
 *
 *  Author: Raag Jadav <raag.jadav@intel.com>
 */

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <unistd.h>

#define ETH_P_DEAD	0xdead
#define MTU		1500

FILE *fp;
unsigned long flen;

char *buf;
int sockfd;
struct ether_header *eh;
struct ether_addr *destmac;
struct sockaddr_ll sockaddr;

struct iovec *ring;
struct tpacket_req req;

int open_file(char *path, char *mode)
{
	struct stat st;

	/* Open file in given mode */
	fp = fopen(path, mode);
	if (!fp) {
		perror("fopen");
		return -1;
	}

	/* Get file length */
	if (stat(path, &st)) {
		perror("stat");
		return -1;
	}

	flen = st.st_size;

	return 0;
}

int open_sock(int protocol)
{
	/* Open RAW socket */
	sockfd = socket(AF_PACKET, SOCK_RAW, protocol);
	if (sockfd < 0) {
		perror("socket");
		return -1;
	}

	return 0;
}

int prep_send(char *iface)
{
	struct ifreq if_idx;
	struct ifreq if_mac;

	/* Get the index of the interface */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, iface, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) {
		perror("ioctl");
		return -1;
	}

	/* Get the MAC address of the interface */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, iface, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0) {
		perror("ioctl");
		return -1;
	}

	buf = calloc(1, sizeof(struct ether_header) + MTU);
	if (!buf) {
		perror("calloc");
		return -1;
	}

	/* Construct the Ethernet header */
	eh = (struct ether_header *)buf;

	eh->ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
	eh->ether_shost[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
	eh->ether_shost[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
	eh->ether_shost[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
	eh->ether_shost[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
	eh->ether_shost[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
	eh->ether_dhost[0] = destmac->ether_addr_octet[0];
	eh->ether_dhost[1] = destmac->ether_addr_octet[1];
	eh->ether_dhost[2] = destmac->ether_addr_octet[2];
	eh->ether_dhost[3] = destmac->ether_addr_octet[3];
	eh->ether_dhost[4] = destmac->ether_addr_octet[4];
	eh->ether_dhost[5] = destmac->ether_addr_octet[5];

	/* Index of the network device */
	sockaddr.sll_ifindex = if_idx.ifr_ifindex;

	/* Address length */
	sockaddr.sll_halen = ETH_ALEN;

	/* Destination MAC */
	sockaddr.sll_addr[0] = destmac->ether_addr_octet[0];
	sockaddr.sll_addr[1] = destmac->ether_addr_octet[1];
	sockaddr.sll_addr[2] = destmac->ether_addr_octet[2];
	sockaddr.sll_addr[3] = destmac->ether_addr_octet[3];
	sockaddr.sll_addr[4] = destmac->ether_addr_octet[4];
	sockaddr.sll_addr[5] = destmac->ether_addr_octet[5];

	return 0;
}

int prep_recv(char *iface)
{
	int i, ret;
#if 0
	struct ifreq ifopts;

	/* Set interface to promiscuous mode */
	strncpy(ifopts.ifr_name, iface, IFNAMSIZ-1);
	ioctl(sockfd, SIOCGIFFLAGS, &ifopts);
	ifopts.ifr_flags |= IFF_PROMISC;
	ioctl(sockfd, SIOCSIFFLAGS, &ifopts);
#endif

	/* Setup socket for ring buffer */
	req.tp_block_size = 4096;
	req.tp_frame_size = sizeof(struct ether_header) + MTU + 534;	// 534 padding
	req.tp_block_nr = 64;
	req.tp_frame_nr = req.tp_block_nr * (req.tp_block_size / req.tp_frame_size);
	ret = setsockopt(sockfd, SOL_PACKET, PACKET_RX_RING, (void *)&req, sizeof(struct tpacket_req));
	if (ret < 0) {
		perror("PACKET_RX_RING");
		goto out;
	};

	/* Map it */
	buf = mmap(NULL, req.tp_block_size * req.tp_block_nr, PROT_READ | PROT_WRITE, MAP_SHARED, sockfd, 0);
	if (buf == MAP_FAILED) {
		perror("mmap");
		ret = -1;
		goto out;
	}

	/* Setup ring buffer */
	ring = malloc(req.tp_frame_nr * sizeof(struct iovec));
	if (!ring) {
		perror("malloc");
		ret = -1;
		goto out_unmap;
	}

	for (i = 0; i < req.tp_frame_nr; i++) {
		ring[i].iov_base = (void *)((long)buf) + (i * req.tp_frame_size);
		ring[i].iov_len = req.tp_frame_size;
	}

	/* Bind socket to the network device */
	ret = setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, iface, IFNAMSIZ-1);
	if (ret < 0) {
		perror("SO_BINDTODEVICE");
		goto out_ring;
	}

	return 0;

out_ring:
	free(ring);
out_unmap:
	munmap(buf, req.tp_block_size * req.tp_block_nr);
out:
	return ret;
}

int start_send()
{
	size_t data_size, tx_len;

	while (flen)
	{
		if (flen / MTU)
			data_size = MTU;
		else
			data_size = flen;

		tx_len = sizeof(struct ether_header);
		memset(buf + tx_len, 0, data_size);

		if (fread(buf + tx_len, data_size, 1, fp) != 1) {
			perror("fread");
			return -1;
		}

		/* Ethertype/size field */
		eh->ether_type = htons(ETH_P_DEAD);
		tx_len += data_size;

		/* Send packet */
		if (sendto(sockfd, buf, tx_len, 0, (struct sockaddr *)&sockaddr, sizeof(struct sockaddr_ll)) < 0) {
			perror("sendto");
			return -1;
		}

		flen -= data_size;
	}

	return 0;
}

int start_recv(char *iface)
{
	size_t eh_len = sizeof(struct ether_header);
	size_t frame_size = eh_len + MTU;
	struct ifreq if_mac;
	struct pollfd pfd;
	int i;

	/* Get the MAC address of the interface */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, iface, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0) {
		perror("ioctl");
		return -1;
	}

	/* Sleep when nothing's happening */
	pfd.fd = sockfd;
	pfd.events = POLLIN | POLLERR;
	pfd.revents = 0;
	if (poll(&pfd, 1, -1) < 0) {
		perror("poll");
		return -1;
	}

	for (i = 0;;) {
		while(*(unsigned long *)ring[i].iov_base & TP_STATUS_USER) {
			struct tpacket_hdr *th = ring[i].iov_base;
			char *bp = (char *)th + th->tp_mac;
			eh = (struct ether_header *)bp;

			/* Check if the packet is for me */
			if (eh->ether_dhost[0] == ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0] &&
					eh->ether_dhost[1] == ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1] &&
					eh->ether_dhost[2] == ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2] &&
					eh->ether_dhost[3] == ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3] &&
					eh->ether_dhost[4] == ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4] &&
					eh->ether_dhost[5] == ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5]) {

				if (fwrite(bp + eh_len, th->tp_len - eh_len, 1, fp) != 1) {
					perror("fwrite");
					return -1;
				}

				/* Tell the kernel this packet is done with */
				th->tp_status = TP_STATUS_KERNEL;

				if (th->tp_len < frame_size)
					return 0;

				i = (i == req.tp_frame_nr - 1) ? 0 : i + 1;
			}
		}
	}
}

int maccp_send(char *iface, char *path)
{
	int ret;

	ret = open_file(path, "rb");
	if (ret)
		goto out;

	ret = open_sock(IPPROTO_RAW);
	if (ret)
		goto out_file;

	ret = prep_send(iface);
	if (ret)
		goto out_sock;

	ret = start_send();

	free(buf);
out_sock:
	close(sockfd);
out_file:
	fclose(fp);
out:
	return ret;
}

int maccp_recv(char *iface, char *path)
{
	int ret;

	ret = open_file(path, "wb");
	if (ret)
		goto out;

	ret = open_sock(htons(ETH_P_DEAD));
	if (ret)
		goto out_file;

	ret = prep_recv(iface);
	if (ret)
		goto out_sock;

	ret = start_recv(iface);

	free(ring);
	munmap(buf, req.tp_block_size * req.tp_block_nr);
out_sock:
	close(sockfd);
out_file:
	fclose(fp);
out:
	return ret;
}

void usage(char *name)
{
	printf("Usage: %s -s/r <IF> <DEST_MAC>/0 <FILE>\n", name);
	exit(0);
}

void parse_mac(char *mac, char *name)
{
	destmac = ether_aton(mac);
	if (!destmac)
		usage(name);
}

int main(int argc, char *argv[])
{
	int ret;

	if (argc != 5)
		usage(argv[0]);

	if (!strcmp(argv[1], "-s")) {
		parse_mac(argv[3], argv[0]);
		printf("Sending file %s to %s\n", argv[4], argv[3]);
		ret = maccp_send(argv[2], argv[4]);
	} else if (!strcmp(argv[1], "-r")) {
		printf("Receiving file %s\n", argv[4]);
		ret = maccp_recv(argv[2], argv[4]);
	} else {
		usage(argv[0]);
	}

	return ret;
}
