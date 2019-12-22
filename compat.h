#include <time.h>
#include <net/if.h>

#define MIN(a,b) (((a)<(b))?(a):(b))
#define LEN(a) (sizeof(a) / sizeof((a)[0]))

#undef strlcpy
size_t strlcpy(char *, const char *, size_t);

enum { Broadcast, Unicast };

extern int sock;

#define N_TIMERS 3
extern int timers[];
extern struct in_addr server;
extern struct in_addr client;

void open_socket(const char *ifname);
void close_socket(void);
ssize_t udpsend(void *data, size_t n, int how);
ssize_t udprecv(void *data, size_t n);
void get_hw_addr(const char *ifname, unsigned char *hwaddr);
void create_timers(int recreate);
void setgw(struct in_addr gw);

#ifdef __linux__

#include <sys/timerfd.h>

#else

int timerfd_gettime(int fd, struct itimerspec *curr_value);
int timerfd_settime(int fd, int flags,
					const struct itimerspec *new_value,
					struct itimerspec *old_value);

#endif
