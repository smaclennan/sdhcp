#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "arg.h"
#include "util.h"

typedef struct bootp {
	unsigned char op      [1];
	unsigned char htype   [1];
	unsigned char hlen    [1];
	unsigned char hops    [1];
	unsigned char xid     [4];
	unsigned char secs    [2];
	unsigned char flags   [2];
	unsigned char ciaddr  [4];
	unsigned char yiaddr  [4];
	unsigned char siaddr  [4];
	unsigned char giaddr  [4];
	unsigned char chaddr  [16];
	unsigned char sname   [64];
	unsigned char file    [128];
	unsigned char magic   [4];
	unsigned char optdata [312-4];
} Bootp;

enum {
	DHCPdiscover =       1,
	DHCPoffer,
	DHCPrequest,
	DHCPdecline,
	DHCPack,
	DHCPnak,
	DHCPrelease,
	DHCPinform,
	Timeout0 =         200,
	Timeout1,
	Timeout2,

	Bootrequest =        1,
	Bootreply =          2,
	/* bootp flags */
	Fbroadcast =   1 << 15,

	OBpad =              0,
	OBmask =             1,
	OBrouter =           3,
	OBnameserver =       5,
	OBdnsserver =        6,
	OBhostname =        12,
	OBdomainname =		15,
	OBbaddr =           28,
	OBntp =				42,
	ODipaddr =          50, /* 0x32 */
	ODlease =           51,
	ODoverload =        52,
	ODtype =            53, /* 0x35 */
	ODserverid =        54, /* 0x36 */
	ODparams =          55, /* 0x37 */
	ODmessage =         56,
	ODmaxmsg =          57,
	ODrenewaltime =     58,
	ODrebindingtime =   59,
	ODvendorclass =     60,
	ODclientid =        61, /* 0x3d */
	ODtftpserver =      66,
	ODbootfile =        67,
	OBend =            255,
};

static Bootp bp;
static const unsigned char magic[] = { 99, 130, 83, 99 };

static const unsigned char params[] = {
	OBmask, OBrouter, OBdnsserver, OBdomainname, OBntp,
	ODlease, ODrenewaltime, ODrebindingtime
};

/* One socket to rule them all */
int sock = -1;

/* conf */
unsigned char xid[sizeof(bp.xid)];
unsigned char hwaddr[ETHER_ADDR_LEN];
static char hostname[_POSIX_HOST_NAME_MAX + 1];
static time_t starttime;
char *ifname = "eth0";
static unsigned char cid[24];
static int cid_len;
static char *program = "";
int timers[N_TIMERS];
/* sav */
unsigned char server[4];
unsigned char client[4];
static unsigned char mask[4];
static unsigned char router[4];
static unsigned char dns[8];
static unsigned char ntp[8];
static char domainname[64];
static uint32_t renewaltime, rebindingtime, leasetime;

static int dflag = 1; /* change DNS in /etc/resolv.conf ? */
static int iflag = 1; /* set IP ? */
static int fflag = 0; /* run in foreground */

static void
hnput(unsigned char *dst, uint32_t src, size_t n)
{
	unsigned int i;

	for (i = 0; n--; i++)
		dst[i] = (src >> (n * 8)) & 0xff;
}

struct sockaddr *
iptoaddr(struct sockaddr *ifaddr, unsigned char ip[4], int port)
{
	struct sockaddr_in *in = (struct sockaddr_in *)ifaddr;

#ifndef __linux__
	in->sin_len = sizeof(struct sockaddr_in);
#endif
	in->sin_family = AF_INET;
	in->sin_port = htons(port);
	memcpy(&(in->sin_addr), ip, sizeof(in->sin_addr));

	return ifaddr;
}

static void
setip(unsigned char ip[4], unsigned char mask[4])
{
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (fd == -1)
		eprintf("can't set ip, socket:");

	struct ifreq ifreq;
	memset(&ifreq, 0, sizeof(ifreq));

	strlcpy(ifreq.ifr_name, ifname, IF_NAMESIZE);
	iptoaddr(&ifreq.ifr_addr, ip, 0);
	ioctl(fd, SIOCSIFADDR, &ifreq);
	iptoaddr(&ifreq.ifr_addr, mask, 0);
	ioctl(fd, SIOCSIFNETMASK, &ifreq);
	ifreq.ifr_flags = IFF_UP | IFF_RUNNING | IFF_BROADCAST | IFF_MULTICAST;
	ioctl(fd, SIOCSIFFLAGS, &ifreq);

	close(fd);
}

static void
cat(int dfd, char *src)
{
	char buf[BUFSIZ];
	int n, fd;

	if ((fd = open(src, O_RDONLY)) == -1)
		return; /* can't read, but don't error out */
	while ((n = read(fd, buf, sizeof(buf))) > 0)
		write(dfd, buf, n);
	close(fd);
}

static void
setdns(unsigned char dns[])
{
	char buf[128];
	int fd;

	if (dflag == 0)
		return;

	if ((fd = creat("/etc/resolv.conf", 0644)) == -1) {
		weprintf("can't change /etc/resolv.conf:");
		return;
	}
	cat(fd, "/etc/resolv.conf.head");
	if (snprintf(buf, sizeof(buf) - 1, "\nnameserver %d.%d.%d.%d\n",
	         dns[0], dns[1], dns[2], dns[3]) > 0)
		write(fd, buf, strlen(buf));
	if (dns[4])
		if (snprintf(buf, sizeof(buf) - 1, "nameserver %d.%d.%d.%d\n",
					 dns[4], dns[5], dns[6], dns[7]) > 0)
			write(fd, buf, strlen(buf));
	if (*domainname) {
		snprintf(buf, sizeof(buf) - 1, "search %s\n", domainname);
		write(fd, buf, strlen(buf));
	}
	cat(fd, "/etc/resolv.conf.tail");
	close(fd);
}

static void
optget(Bootp *bp, void *data, int opt, int n)
{
	unsigned char *p = bp->optdata;
	unsigned char *top = ((unsigned char *)bp) + sizeof(*bp);
	int code, len;

	while (p < top) {
		code = *p++;
		if (code == OBpad)
			continue;
		if (code == OBend || p == top)
			break;
		len = *p++;
		if (len > top - p)
			break;
		if (code == opt) {
			memcpy(data, p, MIN(len, n));
			break;
		}
		p += len;
	}
}

static unsigned char *
optput(unsigned char *p, int opt, const unsigned char *data, size_t len)
{
	*p++ = opt;
	*p++ = (unsigned char)len;
	memcpy(p, data, len);

	return p + len;
}

static unsigned char *
hnoptput(unsigned char *p, int opt, uint32_t data, size_t len)
{
	*p++ = opt;
	*p++ = (unsigned char)len;
	hnput(p, data, len);

	return p + len;
}

static void
dhcpsend(int type, int how)
{
	unsigned char *p;

	memset(&bp, 0, sizeof(bp));
	hnput(bp.op, Bootrequest, 1);
	hnput(bp.htype, 1, 1);
	hnput(bp.hlen, 6, 1);
	memcpy(bp.xid, xid, sizeof(xid));
	hnput(bp.flags, Fbroadcast, sizeof(bp.flags));
	hnput(bp.secs, time(NULL) - starttime, sizeof(bp.secs));
	memcpy(bp.magic, magic, sizeof(bp.magic));
	memcpy(bp.chaddr, hwaddr, sizeof(hwaddr));
	p = bp.optdata;
	p = hnoptput(p, ODtype, type, 1);
	p = optput(p, ODclientid, cid, cid_len);
	p = optput(p, OBhostname, (unsigned char *)hostname, strlen(hostname));

	switch (type) {
	case DHCPdiscover:
		break;
	case DHCPrequest:
		/* memcpy(bp.ciaddr, client, sizeof bp.ciaddr); */
		p = optput(p, ODipaddr, client, sizeof(client));
		p = optput(p, ODserverid, server, sizeof(server));
		p = optput(p, ODparams, params, sizeof(params));
		break;
	case DHCPrelease:
		memcpy(bp.ciaddr, client, sizeof(client));
		p = optput(p, ODipaddr, client, sizeof(client));
		p = optput(p, ODserverid, server, sizeof(server));
		break;
	}
	*p++ = OBend;

	udpsend(&bp, p - (unsigned char *)&bp, how);
}

static int
dhcprecv(void)
{
	unsigned char type;
	struct pollfd pfd[] = {
		{ .fd = sock, .events = POLLIN },
		{ .fd = timers[0], .events = POLLIN },
		{ .fd = timers[1], .events = POLLIN },
		{ .fd = timers[2], .events = POLLIN },
	};
	uint64_t n;

	while (poll(pfd, LEN(pfd), -1) == -1)
		if (errno != EINTR)
			eprintf("poll:");
	if (pfd[0].revents) {
		memset(&bp, 0, sizeof(bp));
		udprecv(&bp, sizeof(bp));
		optget(&bp, &type, ODtype, sizeof(type));
		return type;
	}
	if (pfd[1].revents) {
		type = Timeout0;
		read(timers[0], &n, sizeof(n));
	}
	if (pfd[2].revents) {
		type = Timeout1;
		read(timers[1], &n, sizeof(n));
	}
	if (pfd[3].revents) {
		type = Timeout2;
		read(timers[2], &n, sizeof(n));
	}
	return type;
}

static void
callout(const char *state)
{
	char buf[32];

	if (*program == 0)
		return;

	setenv("STATE", state, 1);
	snprintf(buf, sizeof(buf), "%u", leasetime);
	setenv("LEASE", buf, 1);
	snprintf(buf, sizeof(buf), "%d.%d.%d.%d", server[0], server[1], server[2], server[3]);
	setenv("SERVER", buf, 1);
	snprintf(buf, sizeof(buf), "%d.%d.%d.%d", client[0], client[1], client[2], client[3]);
	setenv("CLIENT", buf, 1);
	snprintf(buf, sizeof(buf), "%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3]);
	setenv("MASK", buf, 1);
	snprintf(buf, sizeof(buf), "%d.%d.%d.%d", router[0], router[1], router[2], router[3]);
	setenv("ROUTER", buf, 1);
	snprintf(buf, sizeof(buf), "%d.%d.%d.%d", dns[0], dns[1], dns[2], dns[3]);
	setenv("DNS", buf, 1);
	if (dns[4]) {
		snprintf(buf, sizeof(buf), "%d.%d.%d.%d", dns[4], dns[5], dns[6], dns[7]);
		setenv("DNS2", buf, 1);
	}
	if (*domainname)
		setenv("DOMAIN", domainname, 1);
	if (ntp[0]) {
		snprintf(buf, sizeof(buf), "%d.%d.%d.%d", ntp[0], ntp[1], ntp[2], ntp[3]);
		setenv("NTP", buf, 1);
	}
	if (ntp[4]) {
		snprintf(buf, sizeof(buf), "%d.%d.%d.%d", ntp[4], ntp[5], ntp[6], ntp[7]);
		setenv("NTP2", buf, 1);
	}
	system(program);
}

static void
settimeout(int n, const struct itimerspec *ts)
{
	if (timerfd_settime(timers[n], 0, ts, NULL) < 0)
		eprintf("timerfd_settime:");
}

/* sets ts to expire halfway to the expiration of timer n, minimum of 60 seconds */
static void
calctimeout(int n, struct itimerspec *ts)
{
	if (timerfd_gettime(timers[n], ts) < 0)
		eprintf("timerfd_gettime:");
	ts->it_value.tv_nsec /= 2;
	if (ts->it_value.tv_sec % 2)
		ts->it_value.tv_nsec += 500000000;
	ts->it_value.tv_sec /= 2;
	if (ts->it_value.tv_sec < 60) {
		ts->it_value.tv_sec = 60;
		ts->it_value.tv_nsec = 0;
	}
}

static void parse_reply(void)
{
	optget(&bp, mask, OBmask, sizeof(mask));
	optget(&bp, router, OBrouter, sizeof(router));
	optget(&bp, dns, OBdnsserver, sizeof(dns));
	optget(&bp, ntp, OBntp, sizeof(ntp));
	optget(&bp, domainname, OBdomainname, sizeof(domainname));
	optget(&bp, &renewaltime, ODrenewaltime, sizeof(renewaltime));
	optget(&bp, &rebindingtime, ODrebindingtime, sizeof(rebindingtime));
	optget(&bp, &leasetime, ODlease, sizeof(leasetime));
	renewaltime = ntohl(renewaltime);
	rebindingtime = ntohl(rebindingtime);
	leasetime = ntohl(leasetime);
}

static void
run(void)
{
	int forked = 0, t;
	struct itimerspec timeout = { { 0, 0 }, { 0, 0 } };

Init:
	memset(client, 0, sizeof(client));
	dhcpsend(DHCPdiscover, Broadcast);
	timeout.it_value.tv_sec = 1;
	timeout.it_value.tv_nsec = 0;
	settimeout(0, &timeout);
	goto Selecting;
Selecting:
	for (;;) {
		switch (dhcprecv()) {
		case DHCPoffer:
			memcpy(client, bp.yiaddr, sizeof(client));
			optget(&bp, server, ODserverid, sizeof(server));
			goto Requesting;
		case Timeout0:
			goto Init;
		}
	}
Requesting:
	for (t = 4; t <= 64; t *= 2) {
		dhcpsend(DHCPrequest, Broadcast);
		timeout.it_value.tv_sec = t;
		settimeout(0, &timeout);
		for (;;) {
			switch (dhcprecv()) {
			case DHCPack:
				goto Bound;
			case DHCPnak:
				goto Init;
			case Timeout0:
				break;
			default:
				continue;
			}
			break;
		}
	}
	/* no response from DHCPREQUEST after several attempts, go to INIT */
	goto Init;
Bound:
	close_socket(); /* currently raw sockets only */

	parse_reply();
	if (iflag) {
		setip(client, mask);
		setgw(router);
	}
	setdns(dns);
	callout("BOUND");

	if (!forked)
		fputs("Congrats! You should be on the 'net.\n", stdout);
	if (!fflag && !forked) {
		if (fork())
			exit(0);
		create_timers(1);
	}
	forked = 1; /* doesn't hurt to always set this */

Renewed:
	timeout.it_value.tv_sec = renewaltime;
	settimeout(0, &timeout);
	timeout.it_value.tv_sec = rebindingtime;
	settimeout(1, &timeout);
	timeout.it_value.tv_sec = leasetime;
	settimeout(2, &timeout);
	for (;;) {
		switch (dhcprecv()) {
		case Timeout0: /* t1 elapsed */
			goto Renewing;
		case Timeout1: /* t2 elapsed */
			goto Rebinding;
		case Timeout2: /* lease expired */
			goto Init;
		}
	}
Renewing:
	dhcpsend(DHCPrequest, Unicast);
	calctimeout(1, &timeout);
	settimeout(0, &timeout);
	for (;;) {
		switch (dhcprecv()) {
		case DHCPack:
			parse_reply();
			callout("RENEW");
			goto Renewed;
		case Timeout0: /* resend request */
			goto Renewing;
		case Timeout1: /* t2 elapsed */
			goto Rebinding;
		case Timeout2:
		case DHCPnak:
			goto Init;
		}
	}
Rebinding:
	calctimeout(2, &timeout);
	settimeout(0, &timeout);
	dhcpsend(DHCPrequest, Broadcast);
 	for (;;) {
		switch (dhcprecv()) {
		case DHCPack:
			goto Bound;
		case Timeout0: /* resend request */
			goto Rebinding;
		case Timeout2: /* lease expired */
		case DHCPnak:
			goto Init;
		}
	}
}

static void
cleanexit(int unused)
{
	(void)unused;
	dhcpsend(DHCPrelease, Unicast);
	_exit(0);
}

static void
usage(void)
{
	eprintf("usage: %s [-d] [-e program] [-f] [-i] [ifname] [clientid]\n", argv0);
}

static uint8_t fromhex(char nibble)
{
	if (nibble >= '0' && nibble <= '9')
		return nibble - '0';
	else if (nibble >= 'a' && nibble <= 'f')
		return nibble - 'a' + 10;
	else if (nibble >= 'A' && nibble <= 'F')
		return nibble - 'A' + 10;
	else
		eprintf("Bad nibble %c\n", nibble);
	return 0; // unreachable
}

static int str2bytes(const char *str, uint8_t *bytes, int len)
{
	int slen = strlen(str);
	if ((slen & 1) || slen > (len * 2))
		printf("invalid CID");

	while (*str) {
		*bytes = (fromhex(*str++) << 4);
		*bytes++ |= fromhex(*str++);
	}

	return slen / 2;
}

int
main(int argc, char *argv[])
{
	int rnd;

	ARGBEGIN {
	case 'd': /* don't update DNS in /etc/resolv.conf */
		dflag = 0;
		break;
	case 'e': /* run program */
		program = EARGF(usage());
		break;
	case 'f': /* run in foreground */
		fflag = 1;
		break;
	case 'i': /* don't set ip */
		iflag = 0;
		break;
	default:
		usage();
		break;
	} ARGEND;

	if (argc)
		ifname = argv[0]; /* interface name */
	if (argc >= 2) {  /* client-id */
		if (strncmp(argv[1], "0x", 2) == 0)
			cid_len = str2bytes(argv[1] + 2, cid, sizeof(cid));
		else {
			strlcpy((char *)cid, argv[1], sizeof(cid));
			cid_len = strlen((char *)cid);
		}
	}

	signal(SIGTERM, cleanexit);

	if (gethostname(hostname, sizeof(hostname)) == -1)
		eprintf("gethostname:");

	open_socket(ifname);
	get_hw_addr(ifname, hwaddr);

	/* Set interface up.
	 * For BSD we seem to need to set ip to 0.0.0.0.
	 */
	setip(IP(0,0,0,0), IP(255,0,0,0));

	if (cid_len == 0) {
		cid[0] = 1;
		memcpy(cid + 1, hwaddr, ETHER_ADDR_LEN);
		cid_len = ETHER_ADDR_LEN + 1;
	}

	if ((rnd = open("/dev/urandom", O_RDONLY)) == -1)
		eprintf("can't open /dev/urandom to generate unique transaction identifier:");
	read(rnd, xid, sizeof(xid));
	close(rnd);

	create_timers(0);

	starttime = time(NULL);
	run();

	return 0;
}
