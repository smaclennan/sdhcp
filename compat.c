#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>

#include "compat.h"

static uint8_t hwaddr[ETHER_ADDR_LEN];

#ifdef __linux__

void
get_hw_addr(const char *ifname, unsigned char *hwaddr_in)
{
	struct ifreq ifreq;

	memset(&ifreq, 0, sizeof(ifreq));
	strlcpy(ifreq.ifr_name, ifname, IF_NAMESIZE);
	if (ioctl(sock, SIOCGIFHWADDR, &ifreq))
		err(1, "SIOCGIFHWADDR");

	memcpy(hwaddr, ifreq.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
	memcpy(hwaddr_in, ifreq.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
}

void
create_timers(int recreate)
{	/* timerfd survives a fork, don't need to recreate */
	if (recreate == 0)
		for (int i = 0; i < N_TIMERS; ++i) {
			timers[i] = timerfd_create(CLOCK_BOOTTIME, TFD_CLOEXEC);
			if (timers[i] == -1)
				err(1, "timerfd_create:");
		}
}

/*
 * Copy src to string dst of size siz.  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz == 0).
 * Returns strlen(src); if retval >= siz, truncation occurred.
 */
size_t
strlcpy(char *dst, const char *src, size_t dstlen)
{
	size_t srclen = strlen(src);

	if (dstlen > 0) {
		if (dstlen > srclen)
			strcpy(dst, src);
		else {
			strncpy(dst, src, dstlen - 1);
			dst[dstlen - 1] = 0;
		}
	}

	return srclen;
}

#else

#include <ifaddrs.h>
#include <net/if_dl.h>

static struct sockaddr *
iptoaddr(struct sockaddr *ifaddr, struct in_addr ip, int port)
{
	struct sockaddr_in *in = (struct sockaddr_in *)ifaddr;

#ifndef __linux__
	in->sin_len = sizeof(struct sockaddr_in);
#endif
	in->sin_family = AF_INET;
	in->sin_port = htons(port);
	in->sin_addr = ip;

	return ifaddr;
}

void
get_hw_addr(const char *ifname, unsigned char *hwaddr_out)
{
	struct ifaddrs *ifa = NULL;
	struct sockaddr_dl *sa = NULL;

	if (getifaddrs(&ifa))
		err(1, "getifaddrs");

	for (struct ifaddrs *p = ifa; p; p = p->ifa_next) {
		if (p->ifa_addr->sa_family == AF_LINK &&
			strcmp(p->ifa_name, ifname) == 0) {
			sa = (struct sockaddr_dl *)p->ifa_addr;
			if (sa->sdl_type == 1 || sa->sdl_type == 6) { // ethernet
				memcpy(hwaddr, LLADDR(sa), ETHER_ADDR_LEN);
				memcpy(hwaddr_out, hwaddr, ETHER_ADDR_LEN);
				freeifaddrs(ifa);
				return;
			} else
				errx(1, "INVALID %d", sa->sdl_type);
		}
	}

	errx(1, "No interface called '%s'", ifname);
}

#include <signal.h>
#include <errno.h>

static timer_t t_id[N_TIMERS];
static int t_wr_pipe[N_TIMERS];

static void
sigalrm(int sig, siginfo_t *si, void *ctx)
{
	(void)sig; (void)ctx;

	unsigned char n = si->si_value.sival_int;

	if (n < N_TIMERS)
		write(t_wr_pipe[n], &n, sizeof(n));
}

void
create_timers(int recreate)
{
	struct sigaction act = {
		.sa_flags = SA_SIGINFO,
		.sa_sigaction = sigalrm,
	};
	struct sigevent ev = {
		.sigev_notify = SIGEV_SIGNAL,
		.sigev_signo = SIGALRM,
	};

	for (int id = 0; id < N_TIMERS; ++id) {
		ev.sigev_value.sival_int = id;

		if (timer_create(CLOCK_MONOTONIC, &ev, &t_id[id]))
			err(1, "timer_create");
	}

	if (recreate)
		/* the pipes survive the fork() */
		return;

	if (sigaction(SIGALRM, &act, NULL) < 0)
		err(1, "sigaction SIGALRM:");

	for (int id = 0; id < N_TIMERS; ++id) {
		int pipes[2];
		if (pipe(pipes))
			err(1, "pipe");

		timers[id] = pipes[0];		/* read end */
		t_wr_pipe[id] = pipes[1];	/* write end */
	}
}

int
timerfd_gettime(int fd, struct itimerspec *curr_value)
{
	for (int i = 0; i < N_TIMERS; ++i)
		if (timers[i] == fd)
			return timer_gettime(t_id[i], curr_value);

	errno = EBADF;
	return -1;
}

int
timerfd_settime(int fd, int flags,
				const struct itimerspec *new_value,
				struct itimerspec *old_value)
{
	for (int i = 0; i < N_TIMERS; ++i)
		if (timers[i] == fd)
			return timer_settime(t_id[i], flags, new_value, old_value);

	errno = EBADF;
	return -1;
}

#endif

#ifdef __linux__

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/if_packet.h>

/* Fixed bootp header + 312 for optional */
#define BOOTP_SIZE (236 + 312)

static struct pkt {
	struct ether_header ethhdr;
	struct ip     iphdr;
	struct udphdr udphdr;
	uint32_t bootp[BOOTP_SIZE / sizeof(uint32_t)];
} __attribute__((packed)) pkt;

/* pseudo header for udp calc */
static struct pseudohdr
{
	unsigned long  source_ip;
	unsigned long  dest_ip;
	unsigned char  reserved;
	unsigned char  protocol;
	unsigned short udp_length;
	struct udphdr  udphdr;
	unsigned char bootp[BOOTP_SIZE];
} __attribute__((packed)) pseudohdr;

static unsigned char server_mac[ETHER_ADDR_LEN];
static unsigned int ifindex;
static const char *cached_ifname;

/* RFC 1071. */
static uint16_t
chksum16(const void *buf, int count)
{
	int32_t sum = 0, shift;
	const uint16_t *p = buf;

	while (count > 1) {
		sum += *p++;
		count -= 2;
	}

	if (count > 0)
		sum += *p;

	/*  Fold 32-bit sum to 16 bits */
	if ((shift = sum >> 16))
		sum = (sum & 0xffff) + shift;

	return ~sum;
}

/* open a socket */
void
open_socket(const char *ifname)
{
	int bcast = 1;

	if ((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
		err(1, "socket:");

	if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &bcast, sizeof(bcast)) == -1)
		err(1, "setsockopt broadcast:");

	struct ifreq ifreq;
	memset(&ifreq, 0, sizeof(ifreq));
	strlcpy(ifreq.ifr_name, ifname, IF_NAMESIZE);

	if (ioctl(sock, SIOCGIFINDEX, &ifreq))
		err(1, "SIOCGIFINDEX");
	ifindex = ifreq.ifr_ifindex;
	cached_ifname = ifname;
}

void
close_socket(void)
{	/* We close the socket for performance reasons */
	close(sock);
	sock = -1;
}

ssize_t
udpsend(void *data, size_t n, int broadcast)
{
	if (sock == -1)
		open_socket(cached_ifname);

	memset(&pkt, 0, sizeof(pkt));

	if (broadcast) {
		memset(pkt.ethhdr.ether_dhost, 0xff, ETHER_ADDR_LEN);
		pkt.iphdr.ip_dst.s_addr = INADDR_BROADCAST;
	} else {
		memcpy(&pkt.ethhdr.ether_dhost, server_mac, ETHER_ADDR_LEN);
		pkt.iphdr.ip_dst = server;
	}

	memcpy(pkt.ethhdr.ether_shost, hwaddr, ETHER_ADDR_LEN);
	pkt.ethhdr.ether_type = ntohs(ETHERTYPE_IP);

	pkt.iphdr.ip_v = 4;
	pkt.iphdr.ip_hl = 5;
	pkt.iphdr.ip_tos = IPTOS_LOWDELAY;
	pkt.iphdr.ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr) + n);
	pkt.iphdr.ip_id = 0;
	pkt.iphdr.ip_off = htons(0x4000); /* DF set */
	pkt.iphdr.ip_ttl = 16;
	pkt.iphdr.ip_p = IPPROTO_UDP;
	pkt.iphdr.ip_src = client;
	pkt.iphdr.ip_sum = chksum16(&pkt.iphdr, 20);

	pkt.udphdr.uh_sport = htons(68);
	pkt.udphdr.uh_dport = htons(67);
	pkt.udphdr.uh_ulen = htons(sizeof(struct udphdr) + n);

	memcpy(&pkt.bootp, data, n);

	memset(&pseudohdr, 0, sizeof(pseudohdr));
	pseudohdr.source_ip  = pkt.iphdr.ip_src.s_addr;
	pseudohdr.dest_ip    = pkt.iphdr.ip_dst.s_addr;
	pseudohdr.protocol   = pkt.iphdr.ip_p;
	pseudohdr.udp_length = htons(sizeof(struct udphdr) + n);

	memcpy(&pseudohdr.udphdr, &pkt.udphdr, sizeof(struct udphdr));
	memcpy(&pseudohdr.bootp, data, n);
	int header_len = sizeof(pseudohdr) - BOOTP_SIZE + n;
	pkt.udphdr.uh_sum = chksum16(&pseudohdr, header_len);

	struct sockaddr_ll sa;
	memset(&sa, 0, sizeof (sa));
	sa.sll_family = AF_PACKET;
	sa.sll_protocol = htons(ETH_P_IP);
	sa.sll_halen = ETHER_ADDR_LEN;
	memcpy(sa.sll_addr, hwaddr, ETHER_ADDR_LEN);
	sa.sll_ifindex = ifindex;

	size_t len = sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr) + n;
	ssize_t sent;
	while ((sent = sendto(sock, &pkt, len, 0, (struct sockaddr *)&sa, sizeof(sa))) == -1)
		if (errno != EINTR)
			err(1, "sendto:");

	return sent;
}

ssize_t
udprecv(void *data, size_t n)
{
	struct pkt recv;
	int r;

	memset(&recv, 0, sizeof(recv));
	while ((r = read(sock, &recv, sizeof(recv))) == -1)
		if (errno != EINTR)
			err(1, "read");

	r -= sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr);
	if (r < 236)
		return -1; /* too small to be a dhcp packet */
	if (r > (int)n) r = n;

	if (recv.udphdr.uh_sport != htons(67) || recv.udphdr.uh_dport != htons(68))
		return -1; /* not a dhcp packet */

	if (memcmp(recv.bootp + 7, hwaddr, ETHER_ADDR_LEN))
		return -1; /* not our mac */

	memcpy(server_mac, &recv.ethhdr.ether_shost, ETHER_ADDR_LEN);
	memcpy(data, &recv.bootp, r);

	return r;
}

#else

/* open a socket - ifreq will have ifname filled in */
void
open_socket(const char *ifname)
{
	struct ifreq ifreq;
	int set = 1;

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		err(1, "socket:");

	if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &set, sizeof(set)) == -1)
		err(1, "SO_BROADCAST:");

	memset(&ifreq, 0, sizeof(ifreq));
	strlcpy(ifreq.ifr_name, ifname, IF_NAMESIZE);

#ifdef SIOCGIFINDEX
	// SAM I am pretty sure this is not needed
	if (ioctl(sock, SIOCGIFINDEX, &ifreq))
		err(1, "SIOCGIFINDEX:");
#endif

#ifdef SO_BINDTODEVICE
	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, &ifreq, sizeof(ifreq)) == -1)
		err(1, "SO_BINDTODEVICE:");
#endif

	/* needed */
	struct sockaddr addr;
	struct in_addr zero = { 0 };
	iptoaddr(&addr, zero, 68);
	if (bind(sock, (void*)&addr, sizeof(addr)) != 0)
		err(1, "bind:");
}

void close_socket(void) {}

/* sendto UDP wrapper */
ssize_t
udpsend(void *data, size_t n, int broadcast)
{
	struct sockaddr addr;
	socklen_t addrlen = sizeof(addr);
	ssize_t sent;
	struct in_addr ip;
	int flags = 0;

	if (broadcast) {
		ip.s_addr = INADDR_BROADCAST;
		flags |= MSG_DONTROUTE;
	} else
		ip = server;

	iptoaddr(&addr, ip, 67); /* bootp server */
	while ((sent = sendto(sock, data, n, flags, &addr, addrlen)) == -1)
		if (errno != EINTR)
			err(1, "sendto:");

	return sent;
}

/* recvfrom UDP wrapper */
ssize_t
udprecv(void *data, size_t n)
{
	ssize_t r;

	while ((r = recv(sock, data, n, 0)) == -1)
		if (errno != EINTR)
			err(1, "recvfrom:");

	unsigned *bp = data;
	if (memcmp(bp + 7, hwaddr, ETHER_ADDR_LEN))
		return -1; /* not our mac */

	return r;
}

#endif

#ifdef __linux__
void
setgw(struct in_addr gw)
{
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (fd == -1)
		err(1, "can't set gw, socket:");

	struct rtentry rtreq = { .rt_flags = RTF_UP | RTF_GATEWAY };
	((struct sockaddr_in *)&rtreq.rt_gateway)->sin_addr = gw;
	ioctl(fd, SIOCADDRT, &rtreq);

	close(fd);
}
#else
#define RTM_ADDRS ((1 << RTAX_DST) | (1 << RTAX_GATEWAY) | (1 << RTAX_NETMASK))
#define RTM_SEQ 42
#define RTM_FLAGS (RTF_STATIC | RTF_UP | RTF_GATEWAY)

static int
rtmsg_send(int s, int cmd, struct in_addr gw)
{
	struct rtmsg {
		struct rt_msghdr hdr;
		unsigned char data[512];
	} rtmsg;

	memset(&rtmsg, 0, sizeof(rtmsg));
	rtmsg.hdr.rtm_type    = cmd;
	rtmsg.hdr.rtm_flags   = RTM_FLAGS;
	rtmsg.hdr.rtm_version = RTM_VERSION;
	rtmsg.hdr.rtm_seq     = RTM_SEQ;
	rtmsg.hdr.rtm_addrs   = RTM_ADDRS;

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_len = sizeof(sa);
	sa.sin_family = AF_INET;

	unsigned char *cp = rtmsg.data;
	cp += sizeof(struct sockaddr_in);				// DST is zero
	((struct sockaddr_in *)cp)->s_addr = gateway;	// GATEWAY
	cp += sizeof(struct sockaddr_in);
	cp += sizeof(struct sockaddr_in);				// NETMASK is zero

	rtmsg.hdr.rtm_msglen = cp - (unsigned char *)&rtmsg;
	if (write(s, &rtmsg, rtmsg.hdr.rtm_msglen) < 0)
		return -1;

	return 0;
}

void
setgw(struct in_addr gw)
{
	int s = socket(PF_ROUTE, SOCK_RAW, 0);
	if (s < 0)
		err(1, "can't set gw, socket:");

	shutdown(s, SHUT_RD); /* Don't want to read back our messages */

	if (rtmsg_send(s, RTM_ADD, gateway) == 0) {
		close(s);
		return;
	}

	if (errno == EEXIST)
		if (rtmsg_send(s, RTM_CHANGE, gateway) == 0) {
			close(s);
			return;
		}

	close(s);
	err(1, "rtmsg send:");
}
#endif
