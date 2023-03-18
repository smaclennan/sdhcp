#include <time.h>
#include <net/if.h>

#define MIN(a,b) (((a)<(b))?(a):(b))
#define LEN(a) (sizeof(a) / sizeof((a)[0]))

#if (defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN) \
	|| defined(__LITTLE_ENDIAN__) || defined(__LITTLEENDIAN__)
#define PORT67	0x4300
#define PORT68	0x4400
#define MAGIC 0x63538263
#else
#if (defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN) \
	|| defined(__BIG_ENDIAN__)
#define PORT67	67
#define PORT68	68
#define MAGIC 0x63825363
#else
#warning Could not work out endian
#define PORT67 htons(67)
#define PORT68 htons(68)
#define MAGIC  ntohl(0x63825363)
#endif
#endif

extern int sock;
extern const char *ifname;
extern int wait_for_link;

#define N_TIMERS 3
extern int timers[];
extern struct in_addr server;
extern struct in_addr client;

void open_socket(const char *ifname);
void close_socket(void);
ssize_t udpsend(void *data, size_t n, int broadcast);
ssize_t udprecv(void *data, size_t n);
void get_hw_addr(const char *ifname, unsigned char *hwaddr);
void create_timers(int recreate);
void setip(struct in_addr ip, struct in_addr mask);
void setgw(struct in_addr gw);

#ifdef __linux__

#include <sys/timerfd.h>

#else

int timerfd_gettime(int fd, struct itimerspec *curr_value);
int timerfd_settime(int fd, int flags,
					const struct itimerspec *new_value,
					struct itimerspec *old_value);

#endif
