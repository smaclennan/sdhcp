#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>


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
#include <err.h>

#include "compat.h"

/* The xid is redundant on ethernet and wireless networks since we
 * have a MAC. Since the xid is client only, just hardcode it.
 */
#define XID 0x21433412

/* Warning: assumes little endian */
#define MAGIC 0x63538263
#define BROADCAST (1 << 7)

struct bootp {
	uint8_t  op;
	uint8_t  htype;
	uint8_t  hlen;
	uint8_t  hops;			// unused
	uint32_t xid;
	uint16_t secs;			// unused
	uint16_t flags;
	struct in_addr ciaddr;
	struct in_addr yiaddr;
	uint32_t siaddr;		// unused
	uint32_t giaddr;		// unused
	uint64_t chaddr;
	uint64_t chaddr2;		// unused
	uint8_t  sname[64];		// unused
	uint8_t  file[128];		// unused
	// optdata
	// we unroll as much as we can
	uint32_t magic;
	uint8_t  type_id;
	uint8_t  type_len;
	uint8_t  type_data;
	uint8_t  cid_id;
	uint8_t  cid_len;
	uint8_t  optdata[312 - 9];
} __attribute((packed));

_Static_assert(sizeof(struct bootp) == 548, "bootp size");

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

static struct bootp bp;

static const unsigned char params[] = {
	OBmask, OBrouter, OBdnsserver, OBdomainname, OBntp,
	ODlease, ODrenewaltime, ODrebindingtime
};

/* One socket to rule them all */
int sock = -1;

/* conf */
static uint64_t hwaddr64;
static char hostname[_POSIX_HOST_NAME_MAX + 1];
static int hostname_len;
const char *ifname = "eth0";
static char *resolvconf = "/etc/resolv.conf";
static unsigned char cid[24];
static int cid_len;
static char *program;
int timers[N_TIMERS];
/* sav */
struct in_addr server;
struct in_addr client;
static struct in_addr mask;
static struct in_addr router;
static struct in_addr dns[2];
static struct in_addr ntp[2];
static char domainname[64];
static uint32_t renewaltime, rebindingtime, leasetime;

static int dflag = 1; /* change DNS in /etc/resolv.conf ? */
static int iflag = 1; /* set IP ? */
static int fflag;     /* run in foreground */

static void
cat(int dfd, char *src)
{
	char buf[BUFSIZ];
	int n;

	int fd = open(src, O_RDONLY);
	if (fd == -1)
		return; /* can't read, but don't error out */
	while ((n = read(fd, buf, sizeof(buf))) > 0)
		write(dfd, buf, n);
	close(fd);
}

static void
setdns(struct in_addr *dns)
{
	char buf[128];

	if (dflag == 0)
		return;

	int fd = creat(resolvconf, 0644);
	if (fd == -1) {
		warn("can't change %s", resolvconf);
		return;
	}
	cat(fd, "/etc/resolv.conf.head");
	int n = snprintf(buf, sizeof(buf), "\nnameserver %s\n", inet_ntoa(dns[0]));
	if (dns[1].s_addr)
		n += snprintf(buf + n, sizeof(buf) - n, "nameserver %s\n", inet_ntoa(dns[1]));
	if (*domainname)
		n += snprintf(buf + n, sizeof(buf) - n, "search %s\n", domainname);
	write(fd, buf, n);
	cat(fd, "/etc/resolv.conf.tail");
	close(fd);
}

static void
optget(struct bootp *bp, void *data, int opt, int n)
{
	unsigned char *p = &bp->type_id;
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
optput(unsigned char *p, int opt, const void *data, size_t len)
{
	*p++ = opt;
	*p++ = (unsigned char)len;
	memcpy(p, data, len);

	return p + len;
}

static void
dhcpsend(int type, uint16_t broadcast)
{
	struct bootp bootp = {
		.op = 1,	// boot request
		.htype = 1,	// ethernet
		.hlen = ETHER_ADDR_LEN,
		.xid = XID,
		.flags = broadcast,
		.chaddr = hwaddr64,
		.magic = MAGIC,
		.type_id = ODtype,
		.type_len = 1,
		.type_data = type,
		.cid_id = ODclientid,
		.cid_len = cid_len,
	};

	memcpy(bootp.optdata, cid, cid_len);
	uint8_t *p = bootp.optdata + cid_len;
	p = optput(p, OBhostname, (unsigned char *)hostname, hostname_len);

	switch (type) {
	case DHCPdiscover:
		break;
	case DHCPrequest:
		p = optput(p, ODipaddr, &client, sizeof(client));
		p = optput(p, ODserverid, &server, sizeof(server));
		p = optput(p, ODparams, params, sizeof(params));
		break;
	case DHCPrelease:
		bootp.ciaddr = client;
		p = optput(p, ODipaddr, &client, sizeof(client));
		p = optput(p, ODserverid, &server, sizeof(server));
		break;
	}
	*p++ = OBend;

	udpsend(&bootp, p - (uint8_t *)&bootp, broadcast);
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

again:
	while (poll(pfd, LEN(pfd), -1) == -1)
		if (errno != EINTR)
			err(1, "poll:");
	if (pfd[0].revents) {
		memset(&bp, 0, sizeof(bp));
		if (udprecv(&bp, sizeof(bp)) == -1)
			/* Not our packet */
			goto again;
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

	if (!program)
		return;

	setenv("STATE", state, 1);
	setenv("IFNAME", ifname, 1);
	snprintf(buf, sizeof(buf), "%d", getpid());
	setenv("SPID", buf, 1);
	snprintf(buf, sizeof(buf), "%u", leasetime);
	setenv("LEASE", buf, 1);
	setenv("SERVER", inet_ntoa(server), 1);
	setenv("CLIENT", inet_ntoa(client), 1);
	setenv("MASK",   inet_ntoa(mask), 1);
	setenv("ROUTER", inet_ntoa(router), 1);
	if (dns[0].s_addr)
		setenv("DNS", inet_ntoa(dns[0]), 1);
	if (dns[1].s_addr)
		setenv("DNS2", inet_ntoa(dns[1]), 1);
	if (*domainname)
		setenv("DOMAIN", domainname, 1);
	if (ntp[0].s_addr)
		setenv("NTP", inet_ntoa(ntp[0]), 1);
	if (ntp[1].s_addr)
		setenv("NTP2", inet_ntoa(ntp[1]), 1);
	system(program);
}

static void
settimeout(int n, uint32_t seconds)
{
	const struct itimerspec ts = { .it_value.tv_sec = seconds };
	if (timerfd_settime(timers[n], 0, &ts, NULL) < 0)
		err(1, "timerfd_settime:");
}

/* sets timer t to expire halfway to the expiration of timer n, minimum of 60 seconds */
static void
calctimeout(int n, int t)
{
	struct itimerspec ts;

	if (timerfd_gettime(timers[n], &ts) < 0)
		err(1, "timerfd_gettime:");
	ts.it_value.tv_nsec /= 2;
	if (ts.it_value.tv_sec % 2)
		ts.it_value.tv_nsec += 500000000;
	ts.it_value.tv_sec /= 2;
	if (ts.it_value.tv_sec < 60) {
		ts.it_value.tv_sec = 60;
		ts.it_value.tv_nsec = 0;
	}
	if (timerfd_settime(timers[t], 0, &ts, NULL) < 0)
		err(1, "timerfd_settime:");
}

static void
parse_reply(void)
{
	optget(&bp, &mask, OBmask, sizeof(mask));
	optget(&bp, &router, OBrouter, sizeof(router));
	optget(&bp, &dns, OBdnsserver, sizeof(dns));
	optget(&bp, &ntp, OBntp, sizeof(ntp));
	optget(&bp, domainname, OBdomainname, sizeof(domainname));
	optget(&bp, &leasetime, ODlease, sizeof(leasetime));
	leasetime = ntohl(leasetime);

	/* Renew and rebind times are optional. It is faster to just
	 * calculate the times. Assumes: lease > 4s and < ~20 years.
	 */
	renewaltime   = leasetime / 2;
	rebindingtime = leasetime * 7 / 8;
}

static void
run(int fast_start)
{
	int forked = 0;
	uint32_t t;

	if (fast_start)
		goto Requesting;

Init:
	client.s_addr = 0;
	dhcpsend(DHCPdiscover, BROADCAST);
	settimeout(0, 1);
	goto Selecting;
Selecting:
	for (;;) {
		switch (dhcprecv()) {
		case DHCPoffer:
			client = bp.yiaddr;
			optget(&bp, &server, ODserverid, sizeof(server));
			goto Requesting;
		case Timeout0:
			goto Init;
		}
	}
Requesting:
	for (t = 4; t <= 64; t *= 2) {
		dhcpsend(DHCPrequest, BROADCAST);
		settimeout(0, t);
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

	if (!forked)
		fputs("Congrats! You should be on the 'net.\n", stdout);
	if (!fflag && !forked) {
		if (fork())
			exit(0);
		create_timers(1);
	}
	forked = 1; /* doesn't hurt to always set this */

	/* call after fork() to get pid */
	callout("BOUND");

Renewed:
	settimeout(0, renewaltime);
	settimeout(1, rebindingtime);
	settimeout(2, leasetime);
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
	dhcpsend(DHCPrequest, 0);
	calctimeout(1, 0);
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
	calctimeout(2, 0);
	dhcpsend(DHCPrequest, BROADCAST);
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
	dhcpsend(DHCPrelease, 0);
	_exit(0);
}

static void __attribute__((noreturn))
usage(int rc)
{
	errx(rc, " [-c client_ip] [-d] [-e program] [-f] [-i] [-r resolv.conf]\n"
		 "\t[ifname] [clientid]");
}

static uint8_t
fromhex(char nibble)
{
	if (nibble >= '0' && nibble <= '9')
		return nibble - '0';
	else if (nibble >= 'a' && nibble <= 'f')
		return nibble - 'a' + 10;
	else if (nibble >= 'A' && nibble <= 'F')
		return nibble - 'A' + 10;
	else
		errx(1, "Bad nibble %c\n", nibble);
	return 0; // unreachable
}

static int
str2bytes(const char *str, uint8_t *bytes, int len)
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
	int c, fast_start = 0;

	while ((c = getopt(argc, argv, "c:de:fhir:")) != EOF)
		switch (c) {
		case 'c': // client IP
			if (inet_aton(optarg, &client) == 0)
				errx(1, "Invalid client address '%s'", optarg);
			fast_start = 1;
			break;
		case 'd': /* don't update DNS in /etc/resolv.conf */
			dflag = 0;
			break;
		case 'e': /* run program */
			program = optarg;
			break;
		case 'f': /* run in foreground */
			fflag = 1;
			break;
		case 'h':
			usage(0);
		case 'i': /* don't set ip */
			iflag = 0;
			break;
		case 'r': /* resolv.conf filename */
			resolvconf = optarg;
			break;
		default:
			usage(1);
		}

	if (optind < argc)
		ifname = argv[optind++]; /* interface name */
	if (optind < argc) {  /* client-id */
		char *id = argv[optind];
		if (*id == '0' && *(id + 1) == 'x')
			id += 2; // backwards compatibility
		cid_len = str2bytes(id, cid, sizeof(cid));
	}

	signal(SIGTERM, cleanexit);

	if (gethostname(hostname, sizeof(hostname)) == -1)
		err(1, "gethostname:");
	hostname_len = strlen(hostname);

	/* Set interface up.
	 * For BSD we seem to need to set ip to 0.0.0.0.
	 */
	struct in_addr zero = { 0 };
	setip(zero, zero);

	open_socket(ifname);

	unsigned char hwaddr[ETHER_ADDR_LEN];
	get_hw_addr(ifname, hwaddr);
	memcpy(&hwaddr64, hwaddr, sizeof(hwaddr));

	if (cid_len == 0) {
		cid[0] = 1;
		memcpy(cid + 1, hwaddr, ETHER_ADDR_LEN);
		cid_len = ETHER_ADDR_LEN + 1;
	}

	create_timers(0);

	run(fast_start);

	return 0;
}
