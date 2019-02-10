#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "../util.h"

#ifdef __linux__

void
get_hw_addr(const char *ifname, unsigned char *hwaddr)
{
	struct ifreq ifreq;

	memset(&ifreq, 0, sizeof(ifreq));
	strlcpy(ifreq.ifr_name, ifname, IF_NAMESIZE);
	if (ioctl(sock, SIOCGIFHWADDR, &ifreq))
		eprintf("SIOCGIFHWADDR");

	memcpy(hwaddr, ifreq.ifr_hwaddr.sa_data, sizeof(ifreq.ifr_hwaddr.sa_data));
}

void
create_timers(int recreate)
{	/* timerfd survives a fork, don't need to recreate */
	if (recreate == 0)
		for (int i = 0; i < N_TIMERS; ++i) {
			timers[i] = timerfd_create(CLOCK_BOOTTIME, TFD_CLOEXEC);
			if (timers[i] == -1)
				eprintf("timerfd_create:");
		}
}

#else

#include <ifaddrs.h>
#include <net/if_dl.h>

void
get_hw_addr(const char *ifname, unsigned char *hwaddr)
{
	struct ifaddrs *ifa = NULL;
	struct sockaddr_dl *sa = NULL;

	if (getifaddrs(&ifa))
		eprintf("getifaddrs");

	for (struct ifaddrs *p = ifa; p; p = p->ifa_next) {
		if (p->ifa_addr->sa_family == AF_LINK &&
			strcmp(p->ifa_name, ifname) == 0) {
			sa = (struct sockaddr_dl *)p->ifa_addr;
			if (sa->sdl_type == 1 || sa->sdl_type == 6) { // ethernet
				memcpy(hwaddr, LLADDR(sa), sa->sdl_alen);
				freeifaddrs(ifa);
				return;
			} else
				eprintf("INVALID %d", sa->sdl_type);
		}
	}

	eprintf("No interface called '%s'", ifname);
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
			eprintf("timer_create");
	}

	if (recreate)
		/* the pipes survive the fork() */
		return;

	if (sigaction(SIGALRM, &act, NULL) < 0)
		eprintf("sigaction SIGALRM:");

	for (int id = 0; id < N_TIMERS; ++id) {
		int pipes[2];
		if (pipe(pipes))
			eprintf("pipe");

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

#ifdef USE_RAW_SOCKET

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
	unsigned char bootp[BOOTP_SIZE];
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

/* open a socket - ifreq will have ifname filled in */
void
open_socket(const char *ifname)
{
	int bcast = 1;

	if ((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
		eprintf("socket:");

	if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &bcast, sizeof(bcast)) == -1)
		eprintf("setsockopt broadcast:");

	struct ifreq ifreq;
	memset(&ifreq, 0, sizeof(ifreq));
	strlcpy(ifreq.ifr_name, ifname, IF_NAMESIZE);

	if (ioctl(sock, SIOCGIFINDEX, &ifreq))
		eprintf("SIOCGIFINDEX");
	ifindex = ifreq.ifr_ifindex;
}

void
close_socket(void)
{	/* We close the socket for performance reasons */
	close(sock);
	sock = -1;
}

ssize_t
udpsend(void *data, size_t n, int how)
{
	if (sock == -1)
		open_socket(ifname);

	memset(&pkt, 0, sizeof(pkt));

	if (how == Broadcast) {
		memset(pkt.ethhdr.ether_dhost, 0xff, ETHER_ADDR_LEN);
		pkt.iphdr.ip_dst.s_addr = INADDR_BROADCAST;
	} else {
		memcpy(&pkt.ethhdr.ether_dhost, server_mac, ETHER_ADDR_LEN);
		memcpy(&pkt.iphdr.ip_dst, server, 4);
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
	memcpy(&pkt.iphdr.ip_src, client, 4);
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
	if ((sent = sendto(sock, &pkt, len, 0, (struct sockaddr *)&sa, sizeof(sa))) == -1)
		eprintf("sendto:");

	return sent;
}

ssize_t
udprecv(void *data, size_t n)
{
	struct pkt recv;
	int r;

	memset(&recv, 0, sizeof(recv));
	if ((r = read(sock, &recv, sizeof(recv))) == -1)
		eprintf("read");

	r -= sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr);

	// Make sure it is a dhcp packet
	if (recv.udphdr.uh_sport == htons(67) && recv.udphdr.uh_dport == htons(68) && r > 0) {
		memcpy(server_mac, &recv.ethhdr.ether_shost, ETHER_ADDR_LEN);
		memcpy(data, &recv.bootp, r);
	} else
		memset(data, 0, n);

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
		eprintf("socket:");

	if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &set, sizeof(set)) == -1)
		eprintf("SO_BROADCAST:");

	memset(&ifreq, 0, sizeof(ifreq));
	strlcpy(ifreq.ifr_name, ifname, IF_NAMESIZE);

#ifdef SIOCGIFINDEX
	// SAM I am pretty sure this is not needed
	if (ioctl(sock, SIOCGIFINDEX, &ifreq))
		eprintf("SIOCGIFINDEX:");
#endif

#ifdef SO_BINDTODEVICE
	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, &ifreq, sizeof(ifreq)) == -1)
		eprintf("SO_BINDTODEVICE:");
#endif

	/* needed */
	struct sockaddr addr;
	iptoaddr(&addr, IP(0, 0, 0, 0), 68);
	if (bind(sock, (void*)&addr, sizeof(addr)) != 0)
		eprintf("bind:");
}

void close_socket(void) {}

/* sendto UDP wrapper */
ssize_t
udpsend(void *data, size_t n, int how)
{
	struct sockaddr addr;
	socklen_t addrlen = sizeof(addr);
	ssize_t sent;
	unsigned char ip[4];
	int flags = 0;

	if (how == Broadcast) {
		*(uint32_t *)ip = INADDR_BROADCAST;
		flags |= MSG_DONTROUTE;
	} else
		memcpy(ip, server, 4);

	iptoaddr(&addr, ip, 67); /* bootp server */
	if ((sent = sendto(sock, data, n, flags, &addr, addrlen)) == -1)
		eprintf("sendto:");

	return sent;
}

/* recvfrom UDP wrapper */
ssize_t
udprecv(void *data, size_t n)
{
	ssize_t r;

	if ((r = recv(sock, data, n, 0)) == -1)
		eprintf("recvfrom:");

	return r;
}

#endif
