/*
 * HTTPTerm : HTTP termination for benchmarks.
 * Initial code extracted from HAProxy, copyright below.
 *
 * HA-Proxy : High Availability-enabled HTTP/TCP proxy
 * 2000-2006 - Willy Tarreau - willy AT meta-x DOT org.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * Please refer to RFC2068 or RFC2616 for informations about HTTP protocol, and
 * RFC2965 for informations about cookies usage. More generally, the IETF HTTP
 * Working Group's web site should be consulted for protocol related changes :
 *
 *     http://ftp.ics.uci.edu/pub/ietf/http/
 *
 * Pending bugs (may be not fixed because never reproduced) :
 *   - solaris only : sometimes, an HTTP proxy with only a dispatch address causes
 *     the proxy to terminate (no core) if the client breaks the connection during
 *     the response. Seen on 1.1.8pre4, but never reproduced. May not be related to
 *     the snprintf() bug since requests were simple (GET / HTTP/1.0), but may be
 *     related to missing setsid() (fixed in 1.1.15)
 *   - a proxy with an invalid config will prevent the startup even if disabled.
 *
 * ChangeLog has moved to the CHANGELOG file.
 *
 * TODO:
 *   - handle properly intermediate incomplete server headers. Done ?
 *   - handle hot-reconfiguration
 *   - fix client/server state transition when server is in connect or headers state
 *     and client suddenly disconnects. The server *should* switch to SHUT_WR, but
 *     still handle HTTP headers.
 *   - remove MAX_NEWHDR
 *   - cut this huge file into several ones
 *
 */

#ifdef ENABLE_ACCEPT4
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>

#if defined(__dietlibc__)
#include <strings.h>
#endif

#if defined(ENABLE_POLL)
#include <sys/poll.h>
#endif

#if defined(ENABLE_EPOLL)
#if !defined(USE_MY_EPOLL)
#include <sys/epoll.h>
#else
#include "include/epoll.h"
#endif
#endif

#include "include/mini-clist.h"

#ifndef HTTPTERM_VERSION
#define HTTPTERM_VERSION "1.7.3"
#endif

#ifndef HTTPTERM_DATE
#define HTTPTERM_DATE	"2017/03/02"
#endif

#ifndef SHUT_RD
#define SHUT_RD		0
#endif

#ifndef SHUT_WR
#define SHUT_WR		1
#endif

#ifndef MSG_MORE
#define MSG_MORE        0
#endif

#ifndef SOCK_NONBLOCK
#define SOCK_NONBLOCK   0x800
#endif

/* We'll try to enable SO_REUSEPORT on Linux 2.4 and 2.6 if not defined.
 * There are two families of values depending on the architecture. Those
 * are at least valid on Linux 2.4 and 2.6, reason why we'll rely on the
 * NETFILTER define.
 */
#if !defined(SO_REUSEPORT) && defined(__linux__)
#if    (SO_REUSEADDR == 2)
#define SO_REUSEPORT 15
#elif  (SO_REUSEADDR == 0x0004)
#define SO_REUSEPORT 0x0200
#endif /* SO_REUSEADDR */
#endif /* SO_REUSEPORT */

#ifdef ENABLE_SPLICE
#ifndef F_SETPIPE_SZ
#define F_SETPIPE_SZ (1024 + 7)
#endif

#ifndef __NR_splice
#if defined(__x86_64__)
#define __NR_splice             275
#define __NR_tee                276
#define __NR_vmsplice           278
#elif defined (__i386__)
#define __NR_splice             313
#define __NR_tee                315
#define __NR_vmsplice           316
#elif defined (__arm__)
#define __NR_splice             340
#define __NR_tee                342
#define __NR_vmsplice           343
#elif defined (__mips__)
#define __NR_splice             304
#define __NR_tee                306
#define __NR_vmsplice           307
#endif /* $arch */
#endif /* __NR_splice */

#ifndef SPLICE_F_NONBLOCK
#define SPLICE_F_MOVE     1
#define SPLICE_F_NONBLOCK 2
#define SPLICE_F_MORE     4

#ifndef _syscall4
#define _syscall4(tr, nr, t1, n1, t2, n2, t3, n3, t4, n4)  \
        inline tr nr(t1 n1, t2 n2, t3 n3, t4 n4) {         \
                return syscall(__NR_##nr, n1, n2, n3, n4); \
        }
#endif
#ifndef _syscall6
#define _syscall6(tr, nr, t1, n1, t2, n2, t3, n3, t4, n4, t5, n5, t6, n6) \
        inline tr nr(t1 n1, t2 n2, t3 n3, t4 n4, t5 n5, t6 n6) {          \
                return syscall(__NR_##nr, n1, n2, n3, n4, n5, n6);        \
        }
#endif
static _syscall6(int, splice, int, fdin, loff_t *, off_in, int, fdout, loff_t *, off_out, size_t, len, unsigned long, flags);
static _syscall4(long, vmsplice, int, fd, const struct iovec *, iov, unsigned long, nr_segs, unsigned int, flags);
static _syscall4(long, tee, int, fd_in, int, fd_out, size_t, len, unsigned int, flags);
#endif
#endif

/*
 * BUFSIZE defines the size of a read and write buffer. It is the maximum
 * amount of bytes which can be stored by the proxy for each session. However,
 * when reading HTTP headers, the proxy needs some spare space to add or rewrite
 * headers if needed. The size of this spare is defined with MAXREWRITE. So it
 * is not possible to process headers longer than BUFSIZE-MAXREWRITE bytes. By
 * default, BUFSIZE=16384 bytes and MAXREWRITE=BUFSIZE/2, so the maximum length
 * of headers accepted is 8192 bytes, which is in line with Apache's limits.
 */
#ifndef BUFSIZE
#define BUFSIZE		4096
#endif

// reserved buffer space for header rewriting. Must not be zero
// otherwise some requests don't get parsed !
#ifndef MAXREWRITE
#define MAXREWRITE	1
#endif

#ifndef RESPSIZE
#define RESPSIZE	65536
#endif

// max # args on a configuration line
#define MAX_LINE_ARGS	40

/* Default connections limit.
 *
 * A system limit can be enforced at build time in order to avoid using httpterm
 * beyond reasonable system limits. For this, just define SYSTEM_MAXCONN to the
 * absolute limit accepted by the system. If the configuration specifies a
 * higher value, it will be capped to SYSTEM_MAXCONN and a warning will be
 * emitted. The only way to override this limit will be to set it via the
 * command-line '-n' argument.
 */
#ifndef SYSTEM_MAXCONN
#define DEFAULT_MAXCONN	2000
#else
#define DEFAULT_MAXCONN	SYSTEM_MAXCONN
#endif

/* how many bits are needed to code the size of an int (eg: 32bits -> 5) */
#define	INTBITS		5

/* this reduces the number of calls to select() by choosing appropriate
 * sheduler precision in milliseconds. It should be near the minimum
 * time that is needed by select() to collect all events. All timeouts
 * are rounded up by adding this value prior to pass it to select().
 */
#define SCHEDULER_RESOLUTION	9

#define TIME_ETERNITY		-1
/* returns the lowest delay amongst <old> and <new>, and respects TIME_ETERNITY */
#define MINTIME(old, new)	(((new)<0)?(old):(((old)<0||(new)<(old))?(new):(old)))
#define SETNOW(a)		(*a=now)

/****** string-specific macros and functions ******/
/* if a > max, then bound <a> to <max>. The macro returns the new <a> */
#define UBOUND(a, max)	({ typeof(a) b = (max); if ((a) > b) (a) = b; (a); })

/* if a < min, then bound <a> to <min>. The macro returns the new <a> */
#define LBOUND(a, min)	({ typeof(a) b = (min); if ((a) < b) (a) = b; (a); })

/* returns 1 only if only zero or one bit is set in X, which means that X is a
 * power of 2, and 0 otherwise */
#define POWEROF2(x) (((x) & ((x)-1)) == 0)
/*
 * copies at most <size-1> chars from <src> to <dst>. Last char is always
 * set to 0, unless <size> is 0. The number of chars copied is returned
 * (excluding the terminating zero).
 * This code has been optimized for size and speed : on x86, it's 45 bytes
 * long, uses only registers, and consumes only 4 cycles per char.
 */
int strlcpy2(char *dst, const char *src, int size) {
    char *orig = dst;
    if (size) {
	while (--size && (*dst = *src)) {
	    src++; dst++;
	}
	*dst = 0;
    }
    return dst - orig;
}

/*
 * Returns a pointer to an area of <__len> bytes taken from the pool <pool> or
 * dynamically allocated. In the first case, <__pool> is updated to point to
 * the next element in the list.
 */
#define pool_alloc_from(__pool, __len) ({                                      \
    void *__p;                                                                 \
    if ((__p = (__pool)) == NULL)                                              \
	__p = malloc(((__len) >= sizeof (void *)) ? (__len) : sizeof(void *)); \
    else {                                                                     \
	__pool = *(void **)(__pool);                                           \
    }                                                                          \
    __p;                                                                       \
})

/*
 * Puts a memory area back to the corresponding pool.
 * Items are chained directly through a pointer that
 * is written in the beginning of the memory area, so
 * there's no need for any carrier cell. This implies
 * that each memory area is at least as big as one
 * pointer.
 */
#define pool_free_to(__pool, __ptr) ({          \
    *(void **)(__ptr) = (void *)(__pool);       \
    __pool = (void *)(__ptr);                   \
})


#define MEM_OPTIM
#ifdef	MEM_OPTIM
/*
 * Returns a pointer to type <type> taken from the
 * pool <pool_type> or dynamically allocated. In the
 * first case, <pool_type> is updated to point to the
 * next element in the list.
 */
#define pool_alloc(type) ({			\
    void *__p;					\
    if ((__p = pool_##type) == NULL)		\
	__p = malloc(sizeof_##type);		\
    else {					\
	pool_##type = *(void **)pool_##type;	\
    }						\
    __p;					\
})

/*
 * Puts a memory area back to the corresponding pool.
 * Items are chained directly through a pointer that
 * is written in the beginning of the memory area, so
 * there's no need for any carrier cell. This implies
 * that each memory area is at least as big as one
 * pointer.
 */
#define pool_free(type, ptr) ({				\
    *(void **)ptr = (void *)pool_##type;		\
    pool_##type = (void *)ptr;				\
})

#else
#define pool_alloc(type) (calloc(1,sizeof_##type));
#define pool_free(type, ptr) (free(ptr));
#endif	/* MEM_OPTIM */

#define sizeof_task	sizeof(struct task)
#define sizeof_session	sizeof(struct session)
#define sizeof_buffer	sizeof(struct buffer)
#define sizeof_fdtab	sizeof(struct fdtab)

/* different possible states for the sockets */
#define FD_STCLOSE	0
#define FD_STLISTEN	1
#define FD_STCONN	2
#define FD_STREADY	3
#define FD_STERROR	4

/* values for task->state */
#define TASK_IDLE	0
#define TASK_RUNNING	1

/* values for proxy->state */
#define PR_STNEW	0
#define PR_STIDLE	1
#define PR_STRUN	2
#define PR_STSTOPPED	3
#define PR_STPAUSED	4

/* possible actions for the *poll() loops */
#define POLL_LOOP_ACTION_INIT	0
#define POLL_LOOP_ACTION_RUN	1
#define POLL_LOOP_ACTION_CLEAN	2

/* poll mechanisms available */
#define POLL_USE_SELECT         (1<<0)
#define POLL_USE_POLL           (1<<1)
#define POLL_USE_EPOLL          (1<<2)

/* bits for proxy->options */
#define PR_O_HTTP_CLOSE	0x00010000	/* force 'connection: close' in both directions */
#define PR_O_CHK_CACHE	0x00020000	/* require examination of cacheability of the 'set-cookie' field */
#define PR_O_TCP_CLI_KA	0x00040000	/* enable TCP keep-alive on client-side sessions */
#define PR_O_FORCE_CLO	0x00200000	/* enforce the connection close immediately after server response */

/* different possible states for the client side */
#define CL_STHEADERS	0
#define CL_STWAIT	1
#define CL_STDATA	2
#define CL_STPAUSE	3
#define CL_STCLOSE	4

/* possible socket states */
#define SKST_SCR	1	/* client socket shut on the read direction */
#define SKST_SCW	2	/* client socket shut on the write direction */
#define SKST_SSR	4	/* server socket shut on the read direction */
#define SKST_SSW	8	/* server socket shut on the write direction */

/* result of an I/O event */
#define	RES_SILENT	0	/* didn't happen */
#define RES_DATA	1	/* data were sent or received */
#define	RES_NULL	2	/* result is 0 (read == 0), or connect without need for writing */
#define RES_ERROR	3	/* result -1 or error on the socket (eg: connect()) */

/* modes of operation (global.mode) */
#define	MODE_DEBUG	1
#define	MODE_DAEMON	8
#define	MODE_QUIET	16
#define	MODE_CHECK	32
#define	MODE_VERBOSE	64
#define	MODE_STARTING	128
#define	MODE_FOREGROUND	256

/* configuration sections */
#define CFG_NONE	0
#define CFG_GLOBAL	1
#define CFG_LISTEN	2

#define ERR_NONE	0	/* no error */
#define ERR_RETRYABLE	1	/* retryable error, may be cumulated */
#define ERR_FATAL	2	/* fatal error, may be cumulated */

#define METH_HEAD       0
#define METH_GET        1
#define METH_POST       2

static char chunk_pattern[] = "1\r\n";
#define CHUNK_LEN (sizeof(chunk_pattern)-1)

/*********************************************************************/

#define LIST_HEAD(a)	((void *)(&(a)))

/*********************************************************************/

struct buffer {
    unsigned int l;			/* data length */
    char *r, *w, *h, *lr;     		/* read ptr, write ptr, last header ptr, last read */
    char *rlim;				/* read limit, used for header rewriting */
    unsigned long long total;		/* total data read */
    char *data;
    char data_buf[BUFSIZE];
};

struct server {
    struct server *next;
    char *id;				/* just for identification */
    unsigned char uweight, eweight;	/* user-specified weight-1, and effective weight-1 */
    unsigned int wscore;		/* weight score, used during srv map computation */
    int cur_sess;			/* number of currently active sessions (including syn_sent) */
    unsigned int cum_sess;		/* cumulated number of sessions really sent to this server */
    struct proxy *proxy;		/* the proxy this server belongs to */
    int resp_time;			/* expected response time in milliseconds */
    int resp_code;			/* expected response code */
    int resp_size;			/* expected response size in bytes */
    int resp_cache;			/* expected cacheability (0=no, 1=yes) */
    char *resp_data;			/* response data if coming from another file */
};

/* The base for all tasks */
struct task {
    struct task *next, *prev;		/* chaining ... */
    struct task *rqnext;		/* chaining in run queue ... */
    struct task *wq;			/* the wait queue this task is in */
    int state;				/* task state : IDLE or RUNNING */
    struct timeval expire;		/* next expiration time for this task, use only for fast sorting */
    int (*process)(struct task *t);	/* the function which processes the task */
    void *context;			/* the task's context */
};

/* WARNING: if new fields are added, they must be initialized in event_accept() */
struct session {
    struct task *task;			/* the task associated with this session */
    /* application specific below */
    struct timeval crexpire;		/* expiration date for a client read  */
    struct timeval cwexpire;		/* expiration date for a client write */
    struct timeval cnexpire;		/* expiration date for a connect */
    char res_cr, res_cw;		/* results of some events */
    struct proxy *proxy;		/* the proxy this socket belongs to */
    int cli_fd;				/* the client side fd */
    int cli_state;			/* state of the client side */
    int sock_st;			/* socket states : SKST_S[CS][RW] */
    int ka;				/* non-zero = keep-alive */
    struct buffer *req;			/* request buffer */
    struct buffer *rep;			/* response buffer */
    unsigned long long to_write;	/* #of response data bytes to write after headers */
    struct sockaddr_storage cli_addr;	/* the client address */
    struct server *srv;			/* the server being used */
    struct {
	struct timeval tv_accept;	/* date of the accept() (beginning of the session) */
	long  t_request;		/* delay before the end of the request arrives, -1 if never occurs */
	long  t_queue;			/* delay before the session gets out of the connect queue, -1 if never occurs */
    } logs;
    unsigned int uniq_id;		/* unique ID used for the traces */
    char *uri;				/* the requested URI within the buffer */
    signed long long req_size;		/* values passed in the URI to override the server's */
    int req_code;
    int req_cache, req_time;
    int req_chunked;
    int req_nosplice;
    int req_random;
    int req_pieces;
    int req_meth;
};

struct listener {
    int fd;				/* the listen socket */
    struct sockaddr_storage addr;	/* the address we listen to */
    struct listener *next;		/* next address or NULL */
};

struct proxy {
    struct listener *listen;		/* the listen addresses and sockets */
    int state;				/* proxy state */
    struct server *srv;			/* known servers */
    int srv_act;			/* # of running servers */
    int tot_wact;			/* total weights of active servers */
    struct server **srv_map;		/* the server map used to apply weights */
    int srv_map_sz;			/* the size of the effective server map */
    int srv_rr_idx;			/* next server to be elected in round robin mode */
    int clitimeout;			/* client I/O timeout (in milliseconds) */
    char *id;				/* proxy id */
    int nbconn;				/* # of active sessions */
    unsigned int cum_conn;		/* cumulated number of processed sessions */
    int maxconn;			/* max # of active sessions */
    int options;			/* PR_O_* ... */
    struct proxy *next;
    struct timeval stop_time;		/* date to stop listening, when stopping != 0 */
    int grace;				/* grace time after stop request */
    struct {
	char *msg400;			/* message for error 400 */
	int len400;			/* message length for error 400 */
	char *msg403;			/* message for error 403 */
	int len403;			/* message length for error 403 */
	char *msg408;			/* message for error 408 */
	int len408;			/* message length for error 408 */
	char *msg500;			/* message for error 500 */
	int len500;			/* message length for error 500 */
	char *msg502;			/* message for error 502 */
	int len502;			/* message length for error 502 */
	char *msg503;			/* message for error 503 */
	int len503;			/* message length for error 503 */
	char *msg504;			/* message for error 504 */
	int len504;			/* message length for error 504 */
    } errmsg;
};

/* info about one given fd */
struct fdtab {
    int (*read)(int fd);	/* read function */
    int (*write)(int fd);	/* write function */
    struct task *owner;		/* the session (or proxy) associated with this fd */
    int state;			/* the state of this fd */
};

struct pipe {
    int pipe[2];
    int start_alignment;
    int stop_alignment;
    int usage;
};

/*********************************************************************/

int cfg_maxpconn = DEFAULT_MAXCONN;	/* # of simultaneous connections per proxy (-N) */
int cfg_maxconn = 0;		/* # of simultaneous connections, (-n) */
char *cfg_cfgfile = NULL;	/* configuration file */
char *progname = NULL;		/* program name */
int  pid;			/* current process id */
char *cmdline_listen = NULL;	/* command-line listen address (ip:port) */
int master_pipe[2], chunked_pipe[CHUNK_LEN][2], slave_pipe[2]; /* pipes used by splice() */
int slave_pipe_usage = 0;
struct pipe chunk_slave_pipe[CHUNK_LEN];
int pipesize = RESPSIZE;
int ignore_err;

/* send zeroes instead of aligned data */
#define GFLAGS_SEND_ZERO	0x1
/* don't use splice */
#define GFLAGS_NO_SPLICE	0x2

/* global options */
static struct {
    int uid;
    int gid;
    int nbproc;
    int maxconn;
    int maxsock;		/* max # of sockets */
    int rlimit_nofile;		/* default ulimit-n value : 0=unset */
    int rlimit_memmax;		/* default ulimit-d in megs value : 0=unset */
    int mode;
    char *chroot;
    char *pidfile;
    unsigned int flags;		/* GFLAGS_* */
} global;

/*********************************************************************/

fd_set	*StaticReadEvent,
    	*StaticWriteEvent;

int cfg_polling_mechanism = 0;     /* POLL_USE_{SELECT|POLL|EPOLL} */

void **pool_session = NULL,
    **pool_buffer   = NULL,
    **pool_fdtab    = NULL,
    **pool_task	    = NULL;

struct proxy *proxy  = NULL;	/* list of all existing proxies */
struct fdtab *fdtab = NULL;	/* array of all the file descriptors */
struct task *rq = NULL;		/* global run queue */
struct task wait_queue[2] = {	/* global wait queue */
    {
	prev:LIST_HEAD(wait_queue[0]),  /* expirable tasks */
	next:LIST_HEAD(wait_queue[0]),
    },
    {
	prev:LIST_HEAD(wait_queue[1]),  /* non-expirable tasks */
	next:LIST_HEAD(wait_queue[1]),
    },
};

static int totalconn = 0;	/* total # of terminated sessions */
static int actconn = 0;		/* # of active sessions */
static int maxfd = 0;		/* # of the highest fd + 1 */
static int listeners = 0;	/* # of listeners */
static struct timeval now = {0,0};	/* the current date at any moment */
static struct proxy defproxy;		/* fake proxy used to assign default values on all instances */

#if defined(ENABLE_EPOLL)
/* FIXME: this is dirty, but at the moment, there's no other solution to remove
 * the old FDs from outside the loop. Perhaps we should export a global 'poll'
 * structure with pointers to functions such as init_fd() and close_fd(), plus
 * a private structure with several pointers to places such as below.
 */

static fd_set *PrevReadEvent = NULL, *PrevWriteEvent = NULL;
#endif

/* this is used to drain data, and as a temporary buffer for sprintf()... */
static char trash[BUFSIZE];
static char common_response[RESPSIZE];
static char common_chunk_resp[RESPSIZE];
static char *random_resp;
static int random_resp_len = RESPSIZE;

const int zero = 0;
const int one = 1;

#define MAX_HOSTNAME_LEN	32
static char hostname[MAX_HOSTNAME_LEN] = "";

const char *HTTP_302 =
	"HTTP/1.0 302 Found\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"Location: "; /* not terminated since it will be concatenated with the URL */

/* same as 302 except that the browser MUST retry with the GET method */
const char *HTTP_303 =
	"HTTP/1.0 303 See Other\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"Location: "; /* not terminated since it will be concatenated with the URL */

const char *HTTP_400 =
	"HTTP/1.0 400 Bad request\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"\r\n"
	"<html><body><h1>400 Bad request</h1>\nYour browser sent an invalid request.\n</body></html>\n";

const char *HTTP_403 =
	"HTTP/1.0 403 Forbidden\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"\r\n"
	"<html><body><h1>403 Forbidden</h1>\nRequest forbidden by administrative rules.\n</body></html>\n";

const char *HTTP_408 =
	"HTTP/1.0 408 Request Time-out\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"\r\n"
	"<html><body><h1>408 Request Time-out</h1>\nYour browser didn't send a complete request in time.\n</body></html>\n";

const char *HTTP_500 =
	"HTTP/1.0 500 Server Error\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"\r\n"
	"<html><body><h1>500 Server Error</h1>\nAn internal server error occured.\n</body></html>\n";

const char *HTTP_502 =
	"HTTP/1.0 502 Bad Gateway\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"\r\n"
	"<html><body><h1>502 Bad Gateway</h1>\nThe server returned an invalid or incomplete response.\n</body></html>\n";

const char *HTTP_503 =
	"HTTP/1.0 503 Service Unavailable\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"\r\n"
	"<html><body><h1>503 Service Unavailable</h1>\nNo server is available to handle this request.\n</body></html>\n";

const char *HTTP_504 =
	"HTTP/1.0 504 Gateway Time-out\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"\r\n"
	"<html><body><h1>504 Gateway Time-out</h1>\nThe server didn't respond in time.\n</body></html>\n";

const char *HTTP_HELP =
	"HTTP/1.0 200\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"\r\n"
	"<html><body><h1>HTTPTerm-" HTTPTERM_VERSION " - " HTTPTERM_DATE "</h1>\n"
	"The following arguments are supported to override the default objects:<br><ul>\n"
	"<li> /?s=&lt;<b>size</b>&gt;[kmg] :\n"
	"  return &lt;<b>size</b>&gt; bytes (may be kB, MB, GB).    Eg: /?s=20k\n"
	"<li> /?r=&lt;<b>retcode</b>&gt;   :\n"
	"  present &lt;<b>retcode</b>&gt; as the HTTP return code.  Eg: /?r=404\n"
	"<li> /?c=&lt;<b>cache</b>&gt;     :\n"
	"  set the return as <b>not cacheable if zero</b>.          Eg: /?c=0\n"
	"<li> /?t=&lt;<b>time</b>&gt;      :\n"
	"  wait &lt;<b>time</b>&gt; milliseconds before responding. Eg: /?t=500\n"
	"<li> /?k=<b>{0|1}</b>             :\n"
	"  Enable transfer encoding chunked with 1 byte chunks\n"
	"<li> /?S=<b>{0|1}</b>             :\n"
	"  Disable/enable use of splice() to send data\n"
	"<li> /?R=<b>{0|1}</b>             :\n"
	"  Disable/enable sending random data (disables splicing)\n"
	"<li> /?p=<b>size</b>              :\n"
	"  Make pieces no larger than this\n"
	"</ul>\n"
	"Note that those arguments may be cumulated on one line separated by\n"
	" the '<b>&amp;</b>' sign :<br><ul>\n"
	"<li><tt>  GET /?s=20k&c=1&t=700 HTTP/1.0      </tt>\n"
	"<li><tt>  GET /?r=500&s=0&c=0&t=1000 HTTP/1.0 </tt>\n"
	"</ul></body></html>\n";

/*********************************************************************/
/*  function prototypes  *********************************************/
/*********************************************************************/

int event_accept(int fd);
int event_cli_read(int fd);
int event_cli_write(int fd);
int process_session(struct task *t);

/*********************************************************************/
/*  general purpose functions  ***************************************/
/*********************************************************************/

void display_version() {
    printf("HTTPTerm version " HTTPTERM_VERSION " " HTTPTERM_DATE"\n");
    printf("Copyright 2000-2017 Willy Tarreau <w@1wt.eu>\n\n");
}

/*
 * This function prints the command line usage and exits
 */
void usage(char *name) {
    display_version();
    fprintf(stderr,
	    "Usage : %s [-f <cfgfile>] [ -vdV"
	    "D ] [ -n <maxconn> ] [ -N <maxpconn> ]\n"
	    "        [ -p <pidfile> ] [ -m <max megs> ] [ -P <pipesize in kB> ]\n"
	    "        -v displays version\n"
	    "        -d enters debug mode ; -db only disables background mode.\n"
	    "        -V enters verbose mode (disables quiet mode)\n"
	    "        -D goes daemon ; implies -q\n"
	    "        -q quiet mode : don't display messages\n"
	    "        -c check mode : only check config file and exit\n"
	    "        -n sets the maximum total # of connections (%d)\n"
	    "        -m limits the usable amount of memory (in MB)\n"
	    "        -N sets the default, per-proxy maximum # of connections (%d)\n"
	    "        -p writes pids of all children to this file\n"
#if defined(ENABLE_EPOLL)
	    "        -de disables epoll() usage even when available\n"
#endif
#if defined(ENABLE_POLL)
	    "        -dp disables poll() usage even when available\n"
#endif
#if defined(ENABLE_SPLICE)
	    "        -dS disables splice() usage even when available\n"
	    "        -P sets splice pipe size in kB\n"
#endif
	    "        -L [<ip>]:<port> adds a listener with one server\n"
	    "        -sf/-st [pid ]* finishes/terminates old pids. Must be last arguments.\n"
	    "        At least one of -f or -L is required.\n"
	    "\n",
	    name, DEFAULT_MAXCONN, cfg_maxpconn);
    exit(1);
}


/*
 * Displays the message on stderr with the date and pid. Overrides the quiet
 * mode during startup.
 */
void Alert(char *fmt, ...) {
    va_list argp;
    struct timeval tv;
    struct tm *tm;

    if (!(global.mode & MODE_QUIET) || (global.mode & (MODE_VERBOSE | MODE_STARTING))) {
	va_start(argp, fmt);

	gettimeofday(&tv, NULL);
	tm=localtime(&tv.tv_sec);
	fprintf(stderr, "[ALERT] %03d/%02d%02d%02d (%d) : ",
		tm->tm_yday, tm->tm_hour, tm->tm_min, tm->tm_sec, (int)getpid());
	vfprintf(stderr, fmt, argp);
	fflush(stderr);
	va_end(argp);
    }
}


/*
 * Displays the message on stderr with the date and pid.
 */
void Warning(char *fmt, ...) {
    va_list argp;
    struct timeval tv;
    struct tm *tm;

    if (!(global.mode & MODE_QUIET) || (global.mode & (MODE_VERBOSE | MODE_STARTING))) {
	va_start(argp, fmt);

	gettimeofday(&tv, NULL);
	tm=localtime(&tv.tv_sec);
	fprintf(stderr, "[WARNING] %03d/%02d%02d%02d (%d) : ",
		tm->tm_yday, tm->tm_hour, tm->tm_min, tm->tm_sec, (int)getpid());
	vfprintf(stderr, fmt, argp);
	fflush(stderr);
	va_end(argp);
    }
}

/*
 * Displays the message on <out> only if quiet mode is not set.
 */
void qfprintf(FILE *out, char *fmt, ...) {
    va_list argp;

    if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE)) {
	va_start(argp, fmt);
	vfprintf(out, fmt, argp);
	fflush(out);
	va_end(argp);
    }
}


/*
 * converts <str> to a struct sockaddr_in* which is locally allocated.
 * The format is "addr:port", where "addr" can be empty or "*" to indicate
 * INADDR_ANY.
 */
struct sockaddr_in *str2sa(char *str) {
    static struct sockaddr_in sa;
    char *c;
    int port;

    memset(&sa, 0, sizeof(sa));
    str=strdup(str);

    if ((c=strrchr(str,':')) != NULL) {
	*c++=0;
	port=atol(c);
    }
    else
	port=0;

    if (*str == '*' || *str == '\0') { /* INADDR_ANY */
	sa.sin_addr.s_addr = INADDR_ANY;
    }
    else if (!inet_pton(AF_INET, str, &sa.sin_addr)) {
	struct hostent *he;

	if ((he = gethostbyname(str)) == NULL) {
	    Alert("Invalid server name: '%s'\n", str);
	}
	else
	    sa.sin_addr = *(struct in_addr *) *(he->h_addr_list);
    }
    sa.sin_port=htons(port);
    sa.sin_family=AF_INET;

    free(str);
    return &sa;
}

/*
 * converts <str> to a two struct in_addr* which are locally allocated.
 * The format is "addr[/mask]", where "addr" cannot be empty, and mask
 * is optionnal and either in the dotted or CIDR notation.
 * Note: "addr" can also be a hostname. Returns 1 if OK, 0 if error.
 */
int str2net(char *str, struct in_addr *addr, struct in_addr *mask) {
    char *c;
    unsigned long len;

    memset(mask, 0, sizeof(*mask));
    memset(addr, 0, sizeof(*addr));
    str=strdup(str);

    if ((c = strrchr(str, '/')) != NULL) {
	*c++ = 0;
        /* c points to the mask */
	if (strchr(c, '.') != NULL) {	    /* dotted notation */
	    if (!inet_pton(AF_INET, c, mask))
		return 0;
	}
	else { /* mask length */
	    char *err;
	    len = strtol(c, &err, 10);
	    if (!*c || (err && *err) || (unsigned)len > 32)
		return 0;
	    if (len)
		mask->s_addr = htonl(0xFFFFFFFFUL << (32 - len));
	    else
		mask->s_addr = 0;
	}
    }
    else {
	mask->s_addr = 0xFFFFFFFF;
    }
    if (!inet_pton(AF_INET, str, addr)) {
	struct hostent *he;

	if ((he = gethostbyname(str)) == NULL) {
	    return 0;
	}
	else
	    *addr = *(struct in_addr *) *(he->h_addr_list);
    }
    free(str);
    return 1;
}


/*
 * converts <str> to a list of listeners which are dynamically allocated.
 * The format is "{addr|'*'}:port[-end][,{addr|'*'}:port[-end]]*", where :
 *  - <addr> can be empty or "*" to indicate INADDR_ANY ;
 *  - <port> is a numerical port from 1 to 65535 ;
 *  - <end> indicates to use the range from <port> to <end> instead (inclusive).
 * This can be repeated as many times as necessary, separated by a coma.
 * The <tail> argument is a pointer to a current list which should be appended
 * to the tail of the new list. The pointer to the new list is returned.
 */
struct listener *str2listener(char *str, struct listener *tail) {
    struct listener *l;
    char *c, *next, *range, *dupstr;
    int port, end;

    next = dupstr = strdup(str);
    
    while (next && *next) {
	struct sockaddr_storage ss;

	str = next;
	/* 1) look for the end of the first address */
	if ((next = strchr(str, ',')) != NULL) {
	    *next++ = 0;
	}

	/* 2) look for the addr/port delimiter, it's the last colon. */
	if ((range = strrchr(str, ':')) == NULL) {
	    Alert("Missing port number: '%s'\n", str);
	    goto fail;
	}	    

	*range++ = 0;

	if (strrchr(str, ':') != NULL) {
	    /* IPv6 address contains ':' */
	    memset(&ss, 0, sizeof(ss));
	    ss.ss_family = AF_INET6;

	    if (!inet_pton(ss.ss_family, str, &((struct sockaddr_in6 *)&ss)->sin6_addr)) {
		Alert("Invalid server address: '%s'\n", str);
		goto fail;
	    }
	}
	else {
	    memset(&ss, 0, sizeof(ss));
	    ss.ss_family = AF_INET;

	    if (*str == '*' || *str == '\0') { /* INADDR_ANY */
		((struct sockaddr_in *)&ss)->sin_addr.s_addr = INADDR_ANY;
	    }
	    else if (!inet_pton(ss.ss_family, str, &((struct sockaddr_in *)&ss)->sin_addr)) {
		struct hostent *he;
		
		if ((he = gethostbyname(str)) == NULL) {
		    Alert("Invalid server name: '%s'\n", str);
		    goto fail;
		}
		else
		    ((struct sockaddr_in *)&ss)->sin_addr =
			*(struct in_addr *) *(he->h_addr_list);
	    }
	}

	/* 3) look for the port-end delimiter */
	if ((c = strchr(range, '-')) != NULL) {
	    *c++ = 0;
	    end = atol(c);
	}
	else {
	    end = atol(range);
	}

	port = atol(range);

	if (port < 1 || port > 65535) {
	    Alert("Invalid port '%d' specified for address '%s'.\n", port, str);
	    goto fail;
	}

	if (end < 1 || end > 65535) {
	    Alert("Invalid port '%d' specified for address '%s'.\n", end, str);
	    goto fail;
	}

	for (; port <= end; port++) {
	    l = (struct listener *)calloc(1, sizeof(struct listener));
	    l->next = tail;
	    tail = l;

	    l->fd = -1;
	    l->addr = ss;
	    if (ss.ss_family == AF_INET6)
		((struct sockaddr_in6 *)(&l->addr))->sin6_port = htons(port);
	    else
		((struct sockaddr_in *)(&l->addr))->sin_port = htons(port);

	} /* end for(port) */
    } /* end while(next) */
    free(dupstr);
    return tail;
 fail:
    free(dupstr);
    return NULL;
}

/* sets <tv> to the current time */
static inline struct timeval *tv_now(struct timeval *tv) {
    if (tv)
	gettimeofday(tv, NULL);
    return tv;
}

/*
 * adds <ms> ms to <from>, set the result to <tv> and returns a pointer <tv>
 */
static struct timeval *tv_delayfrom(struct timeval *tv, struct timeval *from, int ms) {
    if (!tv || !from)
	return NULL;
    tv->tv_usec = from->tv_usec + (ms%1000)*1000;
    tv->tv_sec  = from->tv_sec  + (ms/1000);
    while (tv->tv_usec >= 1000000) {
	tv->tv_usec -= 1000000;
	tv->tv_sec++;
    }
    return tv;
}

/*
 * compares <tv1> and <tv2> : returns 0 if equal, -1 if tv1 < tv2, 1 if tv1 > tv2
 * Must not be used when either argument is eternity. Use tv_cmp2() for that.
 */
static inline int tv_cmp(struct timeval *tv1, struct timeval *tv2) {
    if (tv1->tv_sec < tv2->tv_sec)
	return -1;
    else if (tv1->tv_sec > tv2->tv_sec)
	return 1;
    else if (tv1->tv_usec < tv2->tv_usec)
	return -1;
    else if (tv1->tv_usec > tv2->tv_usec)
	return 1;
    else
	return 0;
}

/*
 * returns the absolute difference, in ms, between tv1 and tv2
 * Must not be used when either argument is eternity.
 */
unsigned long tv_delta(struct timeval *tv1, struct timeval *tv2) {
    int cmp;
    unsigned long ret;
  

    cmp = tv_cmp(tv1, tv2);
    if (!cmp)
	return 0; /* same dates, null diff */
    else if (cmp < 0) {
	struct timeval *tmp = tv1;
	tv1 = tv2;
	tv2 = tmp;
    }
    ret = (tv1->tv_sec - tv2->tv_sec) * 1000;
    if (tv1->tv_usec > tv2->tv_usec)
	ret += (tv1->tv_usec - tv2->tv_usec) / 1000;
    else
	ret -= (tv2->tv_usec - tv1->tv_usec) / 1000;
    return (unsigned long) ret;
}

/*
 * returns the difference, in ms, between tv1 and tv2
 * Must not be used when either argument is eternity.
 */
static inline unsigned long tv_diff(struct timeval *tv1, struct timeval *tv2) {
    unsigned long ret;
  
    ret = (tv2->tv_sec - tv1->tv_sec) * 1000;
    if (tv2->tv_usec > tv1->tv_usec)
	ret += (tv2->tv_usec - tv1->tv_usec) / 1000;
    else
	ret -= (tv1->tv_usec - tv2->tv_usec) / 1000;
    return (unsigned long) ret;
}

/*
 * compares <tv1> and <tv2> modulo 1ms: returns 0 if equal, -1 if tv1 < tv2, 1 if tv1 > tv2
 * Must not be used when either argument is eternity. Use tv_cmp2_ms() for that.
 */
static int tv_cmp_ms(struct timeval *tv1, struct timeval *tv2) {
    if (tv1->tv_sec == tv2->tv_sec) {
	if (tv2->tv_usec >= tv1->tv_usec + 1000)
	    return -1;
	else if (tv1->tv_usec >= tv2->tv_usec + 1000)
	    return 1;
	else
	    return 0;
    }
    else if ((tv2->tv_sec > tv1->tv_sec + 1) ||
	     ((tv2->tv_sec == tv1->tv_sec + 1) && (tv2->tv_usec + 1000000 >= tv1->tv_usec + 1000)))
	return -1;
    else if ((tv1->tv_sec > tv2->tv_sec + 1) ||
	     ((tv1->tv_sec == tv2->tv_sec + 1) && (tv1->tv_usec + 1000000 >= tv2->tv_usec + 1000)))
	return 1;
    else
	return 0;
}

/*
 * returns the remaining time between tv1=now and event=tv2
 * if tv2 is passed, 0 is returned.
 * Must not be used when either argument is eternity.
 */
static inline unsigned long tv_remain(struct timeval *tv1, struct timeval *tv2) {
    unsigned long ret;
  
    if (tv_cmp_ms(tv1, tv2) >= 0)
	return 0; /* event elapsed */

    ret = (tv2->tv_sec - tv1->tv_sec) * 1000;
    if (tv2->tv_usec > tv1->tv_usec)
	ret += (tv2->tv_usec - tv1->tv_usec) / 1000;
    else
	ret -= (tv1->tv_usec - tv2->tv_usec) / 1000;
    return (unsigned long) ret;
}


/*
 * zeroes a struct timeval
 */

static inline struct timeval *tv_eternity(struct timeval *tv) {
    tv->tv_sec = tv->tv_usec = 0;
    return tv;
}

/*
 * returns 1 if tv is null, else 0
 */
static inline int tv_iseternity(struct timeval *tv) {
    if (tv->tv_sec == 0 && tv->tv_usec == 0)
	return 1;
    else
	return 0;
}

/*
 * compares <tv1> and <tv2> : returns 0 if equal, -1 if tv1 < tv2, 1 if tv1 > tv2,
 * considering that 0 is the eternity.
 */
static int tv_cmp2(struct timeval *tv1, struct timeval *tv2) {
    if (tv_iseternity(tv1))
	if (tv_iseternity(tv2))
	    return 0; /* same */
	else
	    return 1; /* tv1 later than tv2 */
    else if (tv_iseternity(tv2))
	return -1; /* tv2 later than tv1 */
    
    if (tv1->tv_sec > tv2->tv_sec)
	return 1;
    else if (tv1->tv_sec < tv2->tv_sec)
	return -1;
    else if (tv1->tv_usec > tv2->tv_usec)
	return 1;
    else if (tv1->tv_usec < tv2->tv_usec)
	return -1;
    else
	return 0;
}

/*
 * compares <tv1> and <tv2> modulo 1 ms: returns 0 if equal, -1 if tv1 < tv2, 1 if tv1 > tv2,
 * considering that 0 is the eternity.
 */
static int tv_cmp2_ms(struct timeval *tv1, struct timeval *tv2) {
    if (tv_iseternity(tv1))
	if (tv_iseternity(tv2))
	    return 0; /* same */
	else
	    return 1; /* tv1 later than tv2 */
    else if (tv_iseternity(tv2))
	return -1; /* tv2 later than tv1 */
    
    if (tv1->tv_sec == tv2->tv_sec) {
	if (tv1->tv_usec >= tv2->tv_usec + 1000)
	    return 1;
	else if (tv2->tv_usec >= tv1->tv_usec + 1000)
	    return -1;
	else
	    return 0;
    }
    else if ((tv1->tv_sec > tv2->tv_sec + 1) ||
	     ((tv1->tv_sec == tv2->tv_sec + 1) && (tv1->tv_usec + 1000000 >= tv2->tv_usec + 1000)))
	return 1;
    else if ((tv2->tv_sec > tv1->tv_sec + 1) ||
	     ((tv2->tv_sec == tv1->tv_sec + 1) && (tv2->tv_usec + 1000000 >= tv1->tv_usec + 1000)))
	return -1;
    else
	return 0;
}

/*
 * returns the remaining time between tv1=now and event=tv2
 * if tv2 is passed, 0 is returned.
 * Returns TIME_ETERNITY if tv2 is eternity.
 */
static unsigned long tv_remain2(struct timeval *tv1, struct timeval *tv2) {
    unsigned long ret;

    if (tv_iseternity(tv2))
	return TIME_ETERNITY;

    if (tv_cmp_ms(tv1, tv2) >= 0)
	return 0; /* event elapsed */

    ret = (tv2->tv_sec - tv1->tv_sec) * 1000;
    if (tv2->tv_usec > tv1->tv_usec)
	ret += (tv2->tv_usec - tv1->tv_usec) / 1000;
    else
	ret -= (tv1->tv_usec - tv2->tv_usec) / 1000;
    return (unsigned long) ret;
}

/*
 * returns the first event between tv1 and tv2 into tvmin.
 * a zero tv is ignored. tvmin is returned.
 */
static inline struct timeval *tv_min(struct timeval *tvmin,
				     struct timeval *tv1, struct timeval *tv2) {

    if (tv_cmp2(tv1, tv2) <= 0)
	*tvmin = *tv1;
    else
	*tvmin = *tv2;

    return tvmin;
}



/***********************************************************/
/*   fd management   ***************************************/
/***********************************************************/



/* Deletes an FD from the fdsets, and recomputes the maxfd limit.
 * The file descriptor is also closed.
 */
static void fd_delete(int fd) {
    FD_CLR(fd, StaticReadEvent);
    FD_CLR(fd, StaticWriteEvent);
#if defined(ENABLE_EPOLL)
    if (PrevReadEvent) {
	FD_CLR(fd, PrevReadEvent);
	FD_CLR(fd, PrevWriteEvent);
    }
#endif

    close(fd);
    fdtab[fd].state = FD_STCLOSE;

    while ((maxfd-1 >= 0) && (fdtab[maxfd-1].state == FD_STCLOSE))
	    maxfd--;
}

/* recomputes the maxfd limit from the fd */
static inline void fd_insert(int fd) {
    if (fd+1 > maxfd)
	maxfd = fd+1;
}

/*************************************************************/
/*   task management   ***************************************/
/*************************************************************/

/* puts the task <t> in run queue <q>, and returns <t> */
static inline struct task *task_wakeup(struct task **q, struct task *t) {
    if (t->state == TASK_RUNNING)
	return t;
    else {
	t->rqnext = *q;
	t->state = TASK_RUNNING;
	return *q = t;
    }
}

/* removes the task <t> from the queue <q>
 * <s> MUST be <q>'s first task.
 * set the run queue to point to the next one, and return it
 */
static inline struct task *task_sleep(struct task **q, struct task *t) {
    if (t->state == TASK_RUNNING) {
	*q = t->rqnext;
	t->state = TASK_IDLE; /* tell that s has left the run queue */
    }
    return *q; /* return next running task */
}

/*
 * removes the task <t> from its wait queue. It must have already been removed
 * from the run queue. A pointer to the task itself is returned.
 */
static inline struct task *task_delete(struct task *t) {
    t->prev->next = t->next;
    t->next->prev = t->prev;
    return t;
}

/*
 * frees a task. Its context must have been freed since it will be lost.
 */
static inline void task_free(struct task *t) {
    pool_free(task, t);
}

/* inserts <task> into its assigned wait queue, where it may already be. In this case, it
 * may be only moved or left where it was, depending on its timing requirements.
 * <task> is returned.
 */
struct task *task_queue(struct task *task) {
    struct task *list = task->wq;
    struct task *start_from;

    /* This is a very dirty hack to queue non-expirable tasks in another queue
     * in order to avoid pulluting the tail of the standard queue. This will go
     * away with the new O(log(n)) scheduler anyway.
     */
    if (tv_iseternity(&task->expire)) {
	/* if the task was queued in the standard wait queue, we must dequeue it */
	if (task->prev) {
	    if (task->wq == LIST_HEAD(wait_queue[1]))
		return task;
	    else {
		task_delete(task);
		task->prev = NULL;
	    }
	}
	list = task->wq = LIST_HEAD(wait_queue[1]);
    } else {
	/* if the task was queued in the eternity queue, we must dequeue it */
	if (task->prev && (task->wq == LIST_HEAD(wait_queue[1]))) {
	    task_delete(task);
	    task->prev = NULL;
	    list = task->wq = LIST_HEAD(wait_queue[0]);
	}
    }

    /* next, test if the task was already in a list */
    if (task->prev == NULL) {
	//	start_from = list;
	start_from = list->prev;
	/* insert the unlinked <task> into the list, searching back from the last entry */
	while (start_from != list && tv_cmp2(&task->expire, &start_from->expire) < 0) {
	    start_from = start_from->prev;
	}
	
	//	  while (start_from->next != list && tv_cmp2(&task->expire, &start_from->next->expire) > 0) {
	//	      start_from = start_from->next;
	//	      stats_tsk_nsrch++;
	//	  }
    }	
    else if (task->prev == list ||
	     tv_cmp2(&task->expire, &task->prev->expire) >= 0) { /* walk right */
	start_from = task->next;
	if (start_from == list || tv_cmp2(&task->expire, &start_from->expire) <= 0) {
	    return task; /* it's already in the right place */
	}

	/* if the task is not at the right place, there's little chance that
	 * it has only shifted a bit, and it will nearly always be queued
	 * at the end of the list because of constant timeouts
	 * (observed in real case).
	 */
#ifndef WE_REALLY_THINK_THAT_THIS_TASK_MAY_HAVE_SHIFTED
	start_from = list->prev; /* assume we'll queue to the end of the list */
	while (start_from != list && tv_cmp2(&task->expire, &start_from->expire) < 0) {
	    start_from = start_from->prev;
	}
#else /* WE_REALLY_... */
	/* insert the unlinked <task> into the list, searching after position <start_from> */
	while (start_from->next != list && tv_cmp2(&task->expire, &start_from->next->expire) > 0) {
	    start_from = start_from->next;
	}
#endif /* WE_REALLY_... */

	/* we need to unlink it now */
	task_delete(task);
    }
    else { /* walk left. */
#ifdef LEFT_TO_TOP	/* not very good */
	start_from = list;
	while (start_from->next != list && tv_cmp2(&task->expire, &start_from->next->expire) > 0) {
	    start_from = start_from->next;
	}
#else
	start_from = task->prev->prev; /* valid because of the previous test above */
	while (start_from != list && tv_cmp2(&task->expire, &start_from->expire) < 0) {
	    start_from = start_from->prev;
	}
#endif
	/* we need to unlink it now */
	task_delete(task);
    }
    task->prev = start_from;
    task->next = start_from->next;
    task->next->prev = task;
    start_from->next = task;
    return task;
}


/*********************************************************************/
/*   more specific functions   ***************************************/
/*********************************************************************/

/* some prototypes */

/*
 * frees  the context associated to a session. It must have been removed first.
 */
static void session_free(struct session *s) {
    if (s->req)
	pool_free(buffer, s->req);
    if (s->rep)
	pool_free(buffer, s->rep);

    pool_free(session, s);
}


/*
 * This function recounts the number of usable active and backup servers for
 * proxy <p>. These numbers are returned into the p->srv_act.
 * This function also recomputes the total active and backup weights.
 */
static void recount_servers(struct proxy *px) {
    struct server *srv;

    px->srv_act = 0; px->tot_wact = 0;
    for (srv = px->srv; srv != NULL; srv = srv->next) {
	px->srv_act++;
	px->tot_wact += srv->eweight + 1;
    }
}

/* This function recomputes the server map for proxy px. It
 * relies on px->tot_wact, so it must be
 * called after recount_servers(). It also expects px->srv_map
 * to be initialized to the largest value needed.
 */
static void recalc_server_map(struct proxy *px) {
    int o, tot;
    struct server *cur, *best;

    tot  = px->tot_wact;

    /* this algorithm gives priority to the first server, which means that
     * it will respect the declaration order for equivalent weights, and
     * that whatever the weights, the first server called will always be
     * the first declard. This is an important asumption for the backup
     * case, where we want the first server only.
     */
    for (cur = px->srv; cur; cur = cur->next)
	cur->wscore = 0;

    for (o = 0; o < tot; o++) {
	int max = 0;
	best = NULL;
	for (cur = px->srv; cur; cur = cur->next) {
	    int v;

	    /* If we are forced to return only one server, we don't want to
	     * go further, because we would return the wrong one due to
	     * divide overflow.
	     */
	    if (tot == 1) {
		best = cur;
		break;
	    }

	    cur->wscore += cur->eweight + 1;
	    v = (cur->wscore + tot) / tot; /* result between 0 and 3 */
	    if (best == NULL || v > max) {
		max = v;
		best = cur;
	    }
	}
	px->srv_map[o] = best;
	best->wscore -= tot;
    }
    px->srv_map_sz = tot;
}

/*
 * This function tries to find a running server for the proxy <px> following
 * the round-robin method.
 * If any server is found, it will be returned and px->srv_rr_idx will be updated
 * to point to the next server. If no valid server is found, NULL is returned.
 */
static inline struct server *get_server_rr(struct proxy *px) {
    if (px->srv_map_sz == 0)
	return NULL;

    if (px->srv_rr_idx < 0 || px->srv_rr_idx >= px->srv_map_sz)
	px->srv_rr_idx = 0;
    return px->srv_map[px->srv_rr_idx++];
}
    
/*
 * this function is called on a read event from a client socket.
 * It normally returns 0, or -1 in case of EAGAIN.
 */
int event_cli_read(int fd) {
    struct task *t = fdtab[fd].owner;
    struct session *s = t->context;
    struct buffer *b = s->req;
    int ret, max;

    if (fdtab[fd].state != FD_STERROR) {
#ifdef FILL_BUFFERS
	while (1)
#else
	do
#endif
	{
	    if (b->l == 0) { /* let's realign the buffer to optimize I/O */
		b->r = b->w = b->h = b->lr  = b->data;
		max = b->rlim - b->data;
	    }
	    else if (b->r > b->w) {
		max = b->rlim - b->r;
	    }
	    else {
		max = b->w - b->r;
		/* FIXME: theorically, if w>0, we shouldn't have rlim < data+size anymore
		 * since it means that the rewrite protection has been removed. This
		 * implies that the if statement can be removed.
		 */
		if (max > b->rlim - b->data)
		    max = b->rlim - b->data;
	    }
	    
	    if (max == 0) {  /* not anymore room to store data */
		FD_CLR(fd, StaticReadEvent);
		break;
	    }
	    
#ifndef MSG_NOSIGNAL
	    {
		int skerr;
		socklen_t lskerr = sizeof(skerr);
		
		getsockopt(fd, SOL_SOCKET, SO_ERROR, &skerr, &lskerr);
		if (skerr)
		    ret = -1;
		else
		    ret = recv(fd, b->r, max, 0);
	    }
#else
	    ret = recv(fd, b->r, max, MSG_NOSIGNAL);
#endif
	    if (ret > 0) {
		b->r += ret;
		b->l += ret;
		s->res_cr = RES_DATA;
		
		if (s->cli_state >= CL_STWAIT) {
		    /* drain data */
		    b->r = b->data;
		    b->l = 0;
		}

		if (b->r == b->data + BUFSIZE) {
		    b->r = b->data; /* wrap around the buffer */
		}

		b->total += ret;
		/* we hope to read more data or to get a close on next round */
		continue;
	    }
	    else if (ret == 0) {
		s->res_cr = RES_NULL;
		break;
	    }
	    else if (errno == EAGAIN) {/* ignore EAGAIN */
		break;
	    }
	    else {
		s->res_cr = RES_ERROR;
		fdtab[fd].state = FD_STERROR;
		break;
	    }
	} /* while(1) */
#ifndef FILL_BUFFERS
	while (0);
#endif
    }
    else {
	s->res_cr = RES_ERROR;
	fdtab[fd].state = FD_STERROR;
    }

    if (s->res_cr != RES_SILENT) {
	if (s->proxy->clitimeout && FD_ISSET(fd, StaticReadEvent))
	    tv_delayfrom(&s->crexpire, &now, s->proxy->clitimeout);
	else
	    tv_eternity(&s->crexpire);
	
	task_wakeup(&rq, t);
    }

    return (s->res_cr == RES_SILENT) ? -1 : 0;
}


/*
 * this function is called on a write event from a client socket.
 * It normally returns 0, or -1 in case of EAGAIN.
 */
int event_cli_write(int fd) {
    struct task *t = fdtab[fd].owner;
    struct session *s = t->context;
    struct buffer *b = s->rep;
    char *data_ptr;
    int ret;
    unsigned long long max;
    int max_loops = 4;

 loop_again:
    if (b->l == 0) { /* let's realign the buffer to optimize I/O */
	b->r = b->w = b->h = b->lr  = b->data;
	max = 0;
    }
    else if (b->r > b->w) {
	max = b->r - b->w;
    }
    else // cannot happen with a file's contents
	max = b->data + BUFSIZE - b->w;
    
    if (fdtab[fd].state != FD_STERROR) {
	data_ptr = b->w;
	if (max == 0) {
	    if (s->to_write > 0) {
		/* we'll send the buffer data, and make sure to align data according to
		 * what was already sent. This will guarantee that all requests will get
		 * the exact same contents. This cannot happen with a file's contents.
		 */
		unsigned int offset;
		char *buffer;
		size_t buffer_len;
		int modulo;

		if (s->req_chunked) {
		    buffer = common_chunk_resp;
		    buffer_len = sizeof(common_chunk_resp);
		    modulo = CHUNK_LEN;
		}
		else if (s->req_random) {
		    buffer = random_resp;
		    buffer_len = random_resp_len;
		    modulo = random_resp_len;
		}
		else {
		    buffer = common_response;
		    buffer_len = sizeof(common_response);
		    modulo = 50;
		}

		offset = (s->req_size - s->to_write) % modulo;
		data_ptr = buffer + offset;
		max = s->to_write;
		if (max > (unsigned long long)(buffer_len - offset))
		    max = (unsigned long long)buffer_len - offset;

	    } else {
		if (s->res_cw != RES_DATA)
		    s->res_cw = RES_NULL;
		task_wakeup(&rq, t);
		tv_eternity(&s->cwexpire);
		FD_CLR(fd, StaticWriteEvent);
		return 0;
	    }
	}

	if (s->req_pieces) {
	    if (max > 4096) {
		max = 4096;
		max = (((unsigned long long)max * ((rand() >> 8) & 0xFFFF)) >> 16) + 1;
	    }
	}

#ifndef MSG_NOSIGNAL
	{
	    int skerr;
	    socklen_t lskerr = sizeof(skerr);

	    getsockopt(fd, SOL_SOCKET, SO_ERROR, &skerr, &lskerr);
	    if (skerr)
		ret = -1;
	    else
		ret = send(fd, data_ptr, max, MSG_DONTWAIT);
	}
#else
	ret = max;
#ifdef ENABLE_SPLICE
	if (!b->l && !(global.flags & GFLAGS_NO_SPLICE) && !s->req_nosplice) {
	    /* dummy data only */
	    if (!s->req_chunked) {

		if ((unsigned long long)slave_pipe_usage < s->to_write) {
		    ret = tee(master_pipe[0], slave_pipe[1], pipesize, SPLICE_F_NONBLOCK);
		    if (ret > 0)
			slave_pipe_usage += ret;
		    ret = max;
		}

		if (slave_pipe_usage) {
		    /* we need to release data from the pipe before calling tee() */
		    ret = splice(slave_pipe[0], NULL, fd, NULL, s->to_write, SPLICE_F_NONBLOCK|((s->ka && (max >= s->to_write)) ? 0 : SPLICE_F_MORE));
		    if (ret > 0) {
			slave_pipe_usage -= ret;
			max = 0;
		    }
		    else if (ret < 0 && errno == EAGAIN) {
			/* Output buffer is full, ensure we don't try again with send() */
			max = 0;
		    }
		}
	    }

	    /* dummy chunked data */
	    else {
		int align;
		int shift;
		struct pipe *p = NULL;
		int i;
		char buf[3];
		struct pipe *not_found = NULL;
		char all_align[CHUNK_LEN];

		align = (s->req_size - s->to_write) % CHUNK_LEN;

	        /* search aligned pipe */
		memset(all_align, 0, sizeof(char) * CHUNK_LEN);
		for (i=0; i<CHUNK_LEN; i++) {
		    if (chunk_slave_pipe[i].start_alignment == align) {
			p = &chunk_slave_pipe[i];
			break;
		    }
		    all_align[chunk_slave_pipe[i].start_alignment]++;
		    if (all_align[chunk_slave_pipe[i].start_alignment] > 1)
			not_found = &chunk_slave_pipe[i];
		}

		/* if not aligned pipe found then adjust other pipe.
		 * "not_found" cannot be NULL.
		 */
		if (!p) {
		    p = not_found;
		    shift = align - p->start_alignment;
		    if (shift < 0)
			shift += CHUNK_LEN;
		    if (p->usage == 0) {
			p->stop_alignment = align;
		    }
		    else if (p->usage < shift) { /* reset */
			read(p->pipe[0], buf, p->usage);
			p->usage = 0;
			p->stop_alignment = align;
		    }
		    else {
			read(p->pipe[0], buf, shift);
			p->usage -= shift;
		    }
		    p->start_alignment = align;
		}

		/* fill data if needed */
		if ((unsigned long long)p->usage < s->to_write) {
		    ret = tee(chunked_pipe[p->stop_alignment][0], p->pipe[1], pipesize,
		              SPLICE_F_NONBLOCK);
		    if (ret > 0) {
			p->usage += ret;
			p->stop_alignment = ( p->stop_alignment + ret ) % CHUNK_LEN;
		    }
		}

		if (p->usage) {
		    /* left the final 3 octet 0\r\n */
		    ret = splice(p->pipe[0], NULL, fd, NULL, s->to_write - 3, SPLICE_F_NONBLOCK|(s->ka ? 0 : SPLICE_F_MORE));
		    if (ret > 0) {
			p->usage -= ret;
			max = 0;
			p->start_alignment = ( p->start_alignment + ret ) % CHUNK_LEN;
		    }
		    else if (ret < 0 && errno == EAGAIN) {
			/* Output buffer is full, ensure we don't try again with send() */
			max = 0;
		    }
		}
	    }
	}
#endif
	if (max && ret)
	    ret = send(fd, data_ptr, max, MSG_DONTWAIT | MSG_NOSIGNAL | ((s->req_pieces || (s->ka && max >= s->to_write + b->l)) ? 0 : MSG_MORE));
#endif

	if (ret > 0) {
	    if (b->l > 0) {
		/* we were working on "standard" data */
		b->l -= ret;
		b->w += ret;
	    
		if (b->w == b->data + BUFSIZE) {
		    b->w = b->data; /* wrap around the buffer */
		}
	    } else {
		/* we were working on dummy data */
		s->to_write -= ret;

		/* in chunked mode, switch to "standard" data for sending
		 * the 3 final digits, followed by a last \r\n for trailers.
		 */
		if (s->to_write == 3) {
		    s->to_write = 0;
		    s->rep->l = 5;
		    s->rep->r = s->rep->h = s->rep->lr = s->rep->w = "0\r\n\r\n";
		    s->rep->r += 5;
		}
	    }
	    
	    s->res_cw = RES_DATA;
	    if (s->req_pieces) {
		if (s->to_write) {
		    s->cli_state = CL_STPAUSE;
		    FD_CLR(s->cli_fd, StaticWriteEvent);
		    /* pause between 1 and 256 ms */
		    tv_delayfrom(&s->cnexpire, &now, 4 << ((rand() >> 16) & 7));
		}
	    }
	    else if (--max_loops > 0)
		goto loop_again;
	}
	else if (ret == 0) {
	    /* nothing written, just make as if we were never called */
//	    s->res_cw = RES_NULL;
	    return 0;
	}
	else if (errno == EAGAIN) { /* ignore EAGAIN */
	    if (s->res_cw == RES_DATA)
		goto return_data;
	    return -1;
	}
	else {
	    s->res_cw = RES_ERROR;
	    fdtab[fd].state = FD_STERROR;
	}
    }
    else {
	s->res_cw = RES_ERROR;
	fdtab[fd].state = FD_STERROR;
    }
 return_data:
    if (s->proxy->clitimeout) {
	tv_delayfrom(&s->cwexpire, &now, s->proxy->clitimeout);
	/* FIXME: to prevent the client from expiring read timeouts during writes,
	 * we refresh it. A solution would be to merge read+write timeouts into a
	 * unique one, although that needs some study particularly on full-duplex
	 * TCP connections. */
	s->crexpire = s->cwexpire;
    }
    else
	tv_eternity(&s->cwexpire);

    task_wakeup(&rq, t);
    return 0;
}



/*
 * returns a message to the client ; the connection is shut down for read,
 * and the request is cleared so that no server connection can be initiated.
 * The client must be in a valid state for this (HEADER, DATA ...).
 * Nothing is performed on the server side.
 * The reply buffer doesn't need to be empty before this.
 */
void client_retnclose(struct session *s, int len, const char *msg) {
    FD_CLR(s->cli_fd, StaticReadEvent);
    FD_SET(s->cli_fd, StaticWriteEvent);
    tv_eternity(&s->crexpire);
    tv_delayfrom(&s->cwexpire, &now, s->proxy->clitimeout);
    shutdown(s->cli_fd, SHUT_RD);
    s->cli_state = CL_STDATA;
    strcpy(s->rep->data, msg);
    s->rep->l = len;
    s->rep->r = s->rep->h = s->rep->lr = s->rep->w = s->rep->data;
    s->rep->r += len;
    s->req->l = 0;
}


/*
 * returns a message into the rep buffer, and flushes the req buffer.
 * The reply buffer doesn't need to be empty before this.
 */
void client_return(struct session *s, int len, const char *msg) {
    strcpy(s->rep->data, msg);
    s->rep->l = len;
    s->rep->r = s->rep->h = s->rep->lr = s->rep->w = s->rep->data;
    s->rep->r += len;
    s->req->l = 0;
}


/*
 * this function is called on a read event from a listen socket, corresponding
 * to an accept. It tries to accept as many connections as possible.
 * It returns 0.
 */
int event_accept(int fd) {
    struct proxy *p = (struct proxy *)fdtab[fd].owner;
    struct session *s;
    struct task *t;
    int cfd = -1;
    int max_accept;

#ifdef ENABLE_ACCEPT4
    static int use_accept = 0;
#else
    static int use_accept = 1;
#endif

    if (global.nbproc > 1)
	    max_accept = 8; /* let other processes catch some connections too */
    else
	    max_accept = -1;

    while (p->nbconn < p->maxconn && max_accept--) {
	struct sockaddr_storage addr;
	socklen_t laddr = sizeof(addr);

#ifdef ENABLE_ACCEPT4
	if (!use_accept) {
	    cfd = accept4(fd, (struct sockaddr *)&addr, &laddr, SOCK_NONBLOCK);
	    if (cfd == -1 && errno == ENOSYS)
		use_accept = 1;
	}
#endif
	if (use_accept) {
	    cfd = accept(fd, (struct sockaddr *)&addr, &laddr);
	    if (cfd != -1)
		fcntl(cfd, F_SETFL, O_NONBLOCK);
	}

	if (cfd == -1) {
	    switch (errno) {
	    case EAGAIN:
	    case EINTR:
	    case ECONNABORTED:
		return 0;	    /* nothing more to accept */
	    case ENFILE:
		return 0;
	    case EMFILE:
		return 0;
	    case ENOBUFS:
	    case ENOMEM:
		return 0;
	    default:
		return 0;
	    }
	}

	if ((s = pool_alloc(session)) == NULL) { /* disable this proxy for a while */
	    Alert("out of memory in event_accept().\n");
	    FD_CLR(fd, StaticReadEvent);
	    p->state = PR_STIDLE;
	    close(cfd);
	    return 0;
	}

	if ((t = pool_alloc(task)) == NULL) { /* disable this proxy for a while */
	    Alert("out of memory in event_accept().\n");
	    FD_CLR(fd, StaticReadEvent);
	    p->state = PR_STIDLE;
	    close(cfd);
	    pool_free(session, s);
	    return 0;
	}

	s->cli_addr = addr;
	if (cfd >= global.maxsock) {
	    Alert("accept(): not enough free sockets. Raise -n argument. Giving up.\n");
	    close(cfd);
	    pool_free(task, t);
	    pool_free(session, s);
	    return 0;
	}

	if (p->options & PR_O_TCP_CLI_KA)
	    setsockopt(cfd, SOL_SOCKET, SO_KEEPALIVE, (char *) &one, sizeof(one));

	t->next = t->prev = t->rqnext = NULL; /* task not in run queue yet */
	t->wq = LIST_HEAD(wait_queue[0]); /* but already has a wait queue assigned */
	t->state = TASK_IDLE;
	t->process = process_session;
	t->context = s;

	s->task = t;
	s->proxy = p;
	s->cli_state = CL_STHEADERS;
	s->sock_st = 0;
	s->ka = 0;
	s->req = s->rep = NULL; /* will be allocated later */
        s->to_write = 0;

	s->res_cr = s->res_cw  = RES_SILENT;
	s->cli_fd = cfd;
	s->srv = NULL;
	s->uri = NULL;
	s->req_code = s->req_size = s->req_cache = s->req_time = -1;
	s->req_chunked = 0;
	s->req_nosplice = 0;
	s->req_random = 0;
	s->req_pieces = 0;

	s->logs.tv_accept = now;
	s->logs.t_request = -1;
	s->logs.t_queue = -1;

	s->uniq_id = totalconn;
	p->cum_conn++;

	if ((global.mode & MODE_DEBUG) && (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))) {
	    struct sockaddr_in sockname;
	    socklen_t namelen = sizeof(sockname);
	    int len;
	    if (addr.ss_family != AF_INET)
		getsockname(cfd, (struct sockaddr *)&sockname, &namelen);

	    if (s->cli_addr.ss_family == AF_INET) {
		char pn[INET_ADDRSTRLEN];
		inet_ntop(AF_INET,
			  (const void *)&((struct sockaddr_in *)&s->cli_addr)->sin_addr,
			  pn, sizeof(pn));

		len = sprintf(trash, "%08x:%s.accept(%04x)=%04x from [%s:%d]\n",
			      s->uniq_id, p->id, (unsigned short)fd, (unsigned short)cfd,
			      pn, ntohs(((struct sockaddr_in *)&s->cli_addr)->sin_port));
	    }
	    else {
		char pn[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6,
			  (const void *)&((struct sockaddr_in6 *)(&s->cli_addr))->sin6_addr,
			  pn, sizeof(pn));

		len = sprintf(trash, "%08x:%s.accept(%04x)=%04x from [%s:%d]\n",
			      s->uniq_id, p->id, (unsigned short)fd, (unsigned short)cfd,
			      pn, ntohs(((struct sockaddr_in6 *)(&s->cli_addr))->sin6_port));
	    }

	    write(1, trash, len);
	}

	if ((s->req = pool_alloc(buffer)) == NULL) { /* no memory */
	    close(cfd); /* nothing can be done for this fd without memory */
	    pool_free(task, t);
	    pool_free(session, s);
	    return 0;
	}

	s->req->data = s->req->data_buf;
	s->req->l = 0;
	s->req->total = 0;
	s->req->h = s->req->r = s->req->lr = s->req->w = s->req->data;	/* r and w will be reset further */
	s->req->rlim = s->req->data + BUFSIZE;
	if (s->cli_state == CL_STHEADERS) /* reserve some space for header rewriting */
	    s->req->rlim -= MAXREWRITE;

	if ((s->rep = pool_alloc(buffer)) == NULL) { /* no memory */
	    pool_free(buffer, s->req);
	    close(cfd); /* nothing can be done for this fd without memory */
	    pool_free(task, t);
	    pool_free(session, s);
	    return 0;
	}
	s->rep->l = 0;
	s->rep->total = 0;
	s->rep->data = s->rep->data_buf;
	s->rep->h = s->rep->r = s->rep->lr = s->rep->w = s->rep->rlim = s->rep->data;

	fdtab[cfd].read  = &event_cli_read;
	fdtab[cfd].write = &event_cli_write;
	fdtab[cfd].owner = t;
	fdtab[cfd].state = FD_STREADY;

	if (event_cli_read(cfd) < 0)
	    FD_SET(cfd, StaticReadEvent);

	setsockopt(cfd, SOL_TCP, TCP_NODELAY, (char *) &one, sizeof(one));

	fd_insert(cfd);

	tv_eternity(&s->cnexpire);
	tv_eternity(&s->crexpire);
	tv_eternity(&s->cwexpire);

	if (s->proxy->clitimeout) {
	    if (FD_ISSET(cfd, StaticReadEvent))
		tv_delayfrom(&s->crexpire, &now, s->proxy->clitimeout);
	    if (FD_ISSET(cfd, StaticWriteEvent))
		tv_delayfrom(&s->cwexpire, &now, s->proxy->clitimeout);
	}

	tv_min(&t->expire, &s->crexpire, &s->cwexpire);

	task_queue(t);
	task_wakeup(&rq, t);

	p->nbconn++;
	actconn++;
	totalconn++;

	// fprintf(stderr, "accepting from %p => %d conn, %d total, task=%p\n", p, actconn, totalconn, t);
    } /* end of while (p->nbconn < p->maxconn) */
    return 0;
}


/*
 * this function writes the string <str> at position <pos> which must be in buffer <b>,
 * and moves <end> just after the end of <str>.
 * <b>'s parameters (l, r, w, h, lr) are recomputed to be valid after the shift.
 * the shift value (positive or negative) is returned.
 * If there's no space left, the move is not done.
 *
 */
int buffer_replace(struct buffer *b, char *pos, char *end, char *str) {
    int delta;
    int len;

    len = strlen(str);
    delta = len - (end - pos);

    if (delta + b->r >= b->data + BUFSIZE)
	return 0;  /* no space left */

    /* first, protect the end of the buffer */
    memmove(end + delta, end, b->data + b->l - end);

    /* now, copy str over pos */
    memcpy(pos, str,len);

    /* we only move data after the displaced zone */
    if (b->r  > pos) b->r  += delta;
    if (b->w  > pos) b->w  += delta;
    if (b->h  > pos) b->h  += delta;
    if (b->lr > pos) b->lr += delta;
    b->l += delta;

    return delta;
}

/* same except that the string length is given, which allows str to be NULL if
 * len is 0.
 */
int buffer_replace2(struct buffer *b, char *pos, char *end, char *str, int len) {
    int delta;

    delta = len - (end - pos);

    if (delta + b->r >= b->data + BUFSIZE)
	return 0;  /* no space left */

    if (b->data + b->l < end)
	/* The data has been stolen, we could have crashed. Maybe we should abort() ? */
	return 0;

    /* first, protect the end of the buffer */
    memmove(end + delta, end, b->data + b->l - end);

    /* now, copy str over pos */
    if (len)
	memcpy(pos, str, len);

    /* we only move data after the displaced zone */
    if (b->r  > pos) b->r  += delta;
    if (b->w  > pos) b->w  += delta;
    if (b->h  > pos) b->h  += delta;
    if (b->lr > pos) b->lr += delta;
    b->l += delta;

    return delta;
}


static int ishex(char s)
{
    return (s >= '0' && s <= '9') || (s >= 'A' && s <= 'F') || (s >= 'a' && s <= 'f');
}


/* This function builds a response and sets
 * indicators accordingly. Note that if <status> is 0, no message is
 * returned.
 */
static inline void srv_return_page(struct session *t) {
    int hlen;
    struct server *srv;

    srv = t->srv;

    if (t->req_code < 0)
	t->req_code = srv->resp_code;

    if (t->req_cache < 0)
	t->req_cache = srv->resp_cache;

    if (srv->resp_size < 0)
	srv->resp_size = 0;

    if (t->req_size < 0)
	t->req_size = srv->resp_size;

    if (t->req_time < 0)
	t->req_time = srv->resp_time;

    if (srv->resp_data) {
	t->rep->data = srv->resp_data;
	t->rep->l = srv->resp_size;
	t->rep->r = srv->resp_data + t->rep->l;
	t->rep->h = t->rep->lr = t->rep->w = t->rep->rlim = t->rep->data;
	t->to_write = 0;
    }
    else {
	if (!t->req_chunked) {
	    hlen = sprintf(t->rep->data,
			   "HTTP/1.1 %03d\r\n"
			   "Connection: %s\r\n"
			   "Content-length: %lld\r\n"
			   "%s"
			   "X-req: size=%ld, time=%ld ms\r\n"
			   "X-rsp: id=%s, code=%d, cache=%d, size=%lld, time=%d ms (%ld real)\r\n"
			   "\r\n",
			   t->req_code,
			   t->ka ? "keep-alive" : "close",
			   t->req_size,
			   t->req_cache ? "" : "Cache-Control: no-cache\r\n",
			   (long)t->req->total, t->logs.t_request,
			   srv->id, t->req_code, t->req_cache,
			   t->req_size, t->req_time,
			   t->logs.t_queue - t->logs.t_request);
	}
	else {
	    hlen = sprintf(t->rep->data,
			   "HTTP/1.1 %03d\r\n"
			   "Connection: %s\r\n"
			   "Transfer-Encoding: chunked\r\n"
			   "%s"
			   "X-req: size=%ld, time=%ld ms\r\n"
			   "X-rsp: id=%s, code=%d, cache=%d, chunked, size=%lld, time=%d ms (%ld real)\r\n"
			   "\r\n",
			   t->req_code,
			   t->ka ? "keep-alive" : "close",
			   t->req_cache ? "" : "Cache-Control: no-cache\r\n",
			   (long)t->req->total, t->logs.t_request,
			   srv->id, t->req_code, t->req_cache,
			   t->req_size, t->req_time,
			   t->logs.t_queue - t->logs.t_request);
	}
	t->to_write = t->req_size;
	t->rep->l = hlen;
	t->rep->r = t->rep->h = t->rep->lr = t->rep->w = t->rep->data;
	t->rep->r += hlen;
    }
    t->req->l = 0;

    if (event_cli_write(t->cli_fd) < 0)
	FD_SET(t->cli_fd, StaticWriteEvent);
}


/*
 * manages the client FSM and its socket. BTW, it also tries to handle the
 * cookie. It returns 1 if a state has changed (and a resync may be needed),
 * 0 else.
 */
int process_cli(struct session *t) {
    int c = t->cli_state;
    struct buffer *req = t->req;
    struct buffer *rep = t->rep;

 loop:

    if (c == CL_STHEADERS) {
	/* now parse the partial (or complete) headers */
	while (req->lr < req->r) { /* this loop only sees one header at each iteration */
	    char *ptr;
	    ptr = req->lr;

	    /* look for the end of the current header */
	    while (ptr < req->r && *ptr != '\n' && *ptr != '\r')
		ptr++;
	    
	    if (ptr == req->h) { /* empty line, end of headers */
		/*
		 * first, let's check that it's not a leading empty line, in
		 * which case we'll ignore and remove it (according to RFC2616).
		 */
		if (req->h == req->data) {
		    /* to get a complete header line, we need the ending \r\n, \n\r, \r or \n too */
		    if (ptr > req->r - 2) {
			/* this is a partial header, let's wait for more to come */
			req->lr = ptr;
			break;
		    }

		    /* now we know that *ptr is either \r or \n,
		     * and that there are at least 1 char after it.
		     */
		    if ((ptr[0] == ptr[1]) || (ptr[1] != '\r' && ptr[1] != '\n'))
			req->lr = ptr + 1; /* \r\r, \n\n, \r[^\n], \n[^\r] */
		    else
			req->lr = ptr + 2; /* \r\n or \n\r */
		    /* ignore empty leading lines */
		    buffer_replace2(req, req->h, req->lr, NULL, 0);
		    req->h = req->lr;
		    continue;
		}

	    end_of_request:
		req->rlim = req->data + BUFSIZE; /* no more rewrite needed */
		t->logs.t_request = tv_diff(&t->logs.tv_accept, &now);

		t->srv = get_server_rr(t->proxy);
		if (!t->srv)
		    goto terminate_client;
		t->srv->cur_sess++;

		tv_eternity(&t->crexpire);

		if (t->req_time < 0)
		    t->req_time = t->srv->resp_time;

		if (t->req_time) {
		    /* we have to wait for the response */
		    tv_delayfrom(&t->cnexpire, &now, t->req_time);
		    t->cli_state = CL_STWAIT;

#ifdef TCP_QUICKACK
		    /* we're going to wait, let's ACK the request */
		    setsockopt(t->cli_fd, SOL_TCP, TCP_QUICKACK, (char *) &one, sizeof(one));
#endif
		    FD_SET(t->cli_fd, StaticReadEvent);
		    req->lr = req->r = req->data;
		    req->l = 0;
		    return 1;
		}

		/* The response must comme immediately, so we'll go through
		 * CL_STDATA.
		 */
		t->logs.t_queue = t->logs.t_request;
		goto immediate_response;
	    }

	    /* to get a complete header line, we need the ending \r\n, \n\r, \r or \n too */
	    if (ptr > req->r - 2) {
		/* this is a partial header, let's wait for more to come */
		req->lr = ptr;
		break;
	    }

	    /* now we know that *ptr is either \r or \n,
	     * and that there are at least 1 char after it.
	     */
	    if ((ptr[0] == ptr[1]) || (ptr[1] != '\r' && ptr[1] != '\n'))
		req->lr = ptr + 1; /* \r\r, \n\n, \r[^\n], \n[^\r] */
	    else
		req->lr = ptr + 2; /* \r\n or \n\r */

	    if ((global.mode & MODE_DEBUG) && (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))) {
		int len, max;
		len = sprintf(trash, "%08x:%s.clihdr[%04x:%04x]: ", t->uniq_id, t->proxy->id, (unsigned  short)t->cli_fd, (unsigned short)-1);
		max = ptr - req->h;
		UBOUND(max, sizeof(trash) - len - 1);
		len += strlcpy2(trash + len, req->h, max + 1);
		trash[len++] = '\n';
		write(1, trash, len);
	    }

	    /* right now we have a full header line */
	    if (!t->uri) {
		char *next;
		t->uri = req->h;
		*ptr = '\0';

		t->req_meth = METH_GET;
		if (*t->uri == 'P')
		    t->req_meth = METH_POST;
		else if (*t->uri == 'H')
		    t->req_meth = METH_HEAD;

		/* keep-alive by default for HTTP/1.1 */
		if (*(ptr-1) == '1')
		    t->ka = 1;

		/* we'll check for the following URIs :
		 * /?{s=<size>|r=<resp>|t=<time>|c=<cache>}[&{...}]
		 * /? to get the help page.
		 */
		if ((next = strchr(t->uri, '?')) != NULL) {
		    char *arg;
		    long result, mult;

		    next += 1;
		    arg = next;
		    if (next == ptr || *next == ' ') {
			client_retnclose(t, strlen(HTTP_HELP), HTTP_HELP);
			return 1;
		    }

		    while (arg + 2 <= ptr && arg[1] == '=') {
			result = strtol(arg + 2, &next, 0);
			if (next > arg + 2) {
			    mult = 0;
			    do {
				if (*next == 'k' || *next == 'K')
				    mult += 10;
				else if (*next == 'm' || *next == 'M')
				    mult += 20;
				else if (*next == 'g' || *next == 'G')
				    mult += 30;
				else
				    break;
				next++;
			    } while (*next);

			    switch (*arg) {
			    case 's':
				if (t->req_meth != METH_HEAD)
				    t->req_size = (long long)result << mult;
				break;
			    case 'r':
				t->req_code = result << mult;
				break;
			    case 't':
				t->req_time = result << mult;
				break;
			    case 'c':
				t->req_cache = result << mult;
				break;
			    case 'k':
				t->req_chunked = result;
				break;
			    case 'S':
				t->req_nosplice = !result;
				break;
			    case 'R':
				t->req_random = result;
				if (result)
				    t->req_nosplice = 1;
				break;
			    case 'p':
				t->req_pieces = result;
				if (result) {
				    t->req_nosplice = 1;
				    setsockopt(t->cli_fd, SOL_TCP, TCP_NODELAY, (char *) &one, sizeof(one));
				}
				break;
			    }
			    arg = next;
			}
			if (*arg == '&')
			    arg++;
			else
			    break;
		    }

		    /* when chunk mode is required, the size is adjusted by the
		     * chunk encoding overhead. each chunk contain 1 data byte.
		     * the final 3 bytes are for the "0\r\n"
		     */
		    if (t->req_chunked)
			t->req_size = t->req_size * (CHUNK_LEN * 2) + 3;
		}
	    }
	    else {
		if (strncasecmp(req->h, "connection:", 11) == 0) {
		    char *p = req->h + 12;

		    while (p < req->lr && (*p == ' ' || *p == '\t'))
			p++;
		    if (*p == 'c' || *p == 'C') // close
			t->ka = 0;
		    else if (*p == 'k' || *p == 'K') // keep-alive
			t->ka = 1;
		}
	    }

	    /* WARNING: ptr is not valid anymore, since the header may have been deleted or truncated ! */
	    req->h = req->lr;
	} /* while (req->lr < req->r) */

	/* end of header processing (even if incomplete) */

	/* horrible hack : we're not interested in headers here anyway, so if a
	 * request is larger than the request buffer, let's simply ignore
	 * remaining headers and go on.
	 */
	if (req->l >= req->rlim - req->data)
	    goto end_of_request;

	if ((req->l < req->rlim - req->data) && ! FD_ISSET(t->cli_fd, StaticReadEvent)) {
	    /* fd in StaticReadEvent was disabled, perhaps because of a previous buffer
	     * full. We cannot loop here since event_cli_read will disable it only if
	     * req->l == rlim-data
	     */
	    FD_SET(t->cli_fd, StaticReadEvent);
	    if (t->proxy->clitimeout)
		tv_delayfrom(&t->crexpire, &now, t->proxy->clitimeout);
	    else
		tv_eternity(&t->crexpire);
	}

	/* note that we don't care about a buffer full since we're not interested
	 * by the request headers.
	 */
	if (t->res_cr == RES_ERROR || t->res_cr == RES_NULL) {
	    /* read error, or last read : give up.  */
	    tv_eternity(&t->crexpire);
	    fd_delete(t->cli_fd);
	    t->cli_state = CL_STCLOSE;
	    return 1;
	}
	else if (tv_cmp2_ms(&t->crexpire, &now) <= 0) {

	    /* read timeout : give up with an error message.
	     */
	    client_retnclose(t, t->proxy->errmsg.len408, t->proxy->errmsg.msg408);
	    return 1;
	}

	return t->cli_state != CL_STHEADERS;
    }
    else if (c == CL_STWAIT) {
	if (!(t->sock_st & SKST_SCR) && (t->res_cr == RES_ERROR))
	    goto terminate_client;

	if (!(t->sock_st & SKST_SCR) && (t->res_cr == RES_NULL)) {
	    /* last read ? */
	    t->sock_st |= SKST_SCR;
	    if (t->sock_st & SKST_SCW)
		goto terminate_client;
	    FD_CLR(t->cli_fd, StaticReadEvent);
	    tv_eternity(&t->crexpire);
	    shutdown(t->cli_fd, SHUT_RD);
	}

	if (tv_cmp2_ms(&t->cnexpire, &now) > 0)
	    return 0; /* nothing changed */

	t->logs.t_queue = tv_diff(&t->logs.tv_accept, &now);
    immediate_response:
	t->cli_state = CL_STDATA;
	tv_eternity(&t->cnexpire);

	/* Note: we also want to drain data */
	FD_SET(t->cli_fd, StaticReadEvent);
	req->lr = req->r = req->data;
	req->l = 0;
	if (t->proxy->clitimeout)
	    tv_delayfrom(&t->cwexpire, &now, t->proxy->clitimeout);

	srv_return_page(t);
	return 1;
    }
    else if (c == CL_STDATA) {
    restart_data:
	if ((!(t->sock_st & SKST_SCW) && t->res_cw == RES_ERROR) ||
	    (!(t->sock_st & SKST_SCR) && t->res_cr == RES_ERROR)) {
	terminate_client:
	    /* read or write error */
	    tv_eternity(&t->crexpire);
	    tv_eternity(&t->cwexpire);
	    fd_delete(t->cli_fd);
	    t->cli_state = CL_STCLOSE;
	    return 1;
	}

	if (!(t->sock_st & SKST_SCR)) {
	    if (t->res_cr == RES_NULL || tv_cmp2_ms(&t->crexpire, &now) <= 0) {
		/* last read, or read timeout */
		t->sock_st |= SKST_SCR;
		if (t->sock_st & SKST_SCW)
		    goto terminate_client;
		FD_CLR(t->cli_fd, StaticReadEvent);
		tv_eternity(&t->crexpire);
		shutdown(t->cli_fd, SHUT_RD);
	    }
	    else {
		if (req->l >= req->rlim - req->data) {
		    /* no room to read more data */
		    if (FD_ISSET(t->cli_fd, StaticReadEvent)) {
			/* stop reading until we get some space */
			FD_CLR(t->cli_fd, StaticReadEvent);
			tv_eternity(&t->crexpire);
		    }
		}
		else {
		    /* there's still some space in the buffer */
		    if (! FD_ISSET(t->cli_fd, StaticReadEvent)) {
			FD_SET(t->cli_fd, StaticReadEvent);
			if (!t->proxy->clitimeout)
			    tv_eternity(&t->crexpire);
			else
			    tv_delayfrom(&t->crexpire, &now, t->proxy->clitimeout);
		    }
		}
	    }
	}

	if (!(t->sock_st & SKST_SCW)) {
	    if (tv_cmp2_ms(&t->cwexpire, &now) <= 0) {
		/* write timeout */
		t->sock_st |= SKST_SCW;
		if (t->sock_st & SKST_SCR)
		    goto terminate_client;
		FD_CLR(t->cli_fd, StaticWriteEvent);
		tv_eternity(&t->cwexpire);
		shutdown(t->cli_fd, SHUT_WR);
	    } else {
		if ((rep->l == 0 && t->to_write == 0)) {
		    if (t->ka) {
			c = t->cli_state = CL_STHEADERS;
			req->lr = req->r = req->data;
			req->l = 0;
			goto loop;
		    }
		    /* this is the end */
		    shutdown(t->cli_fd, SHUT_WR);
		    if (t->req_meth == METH_POST) {
			/* drain possibly pending request data */
			if (recv(t->cli_fd, NULL, INT_MAX, MSG_NOSIGNAL | MSG_TRUNC) == -1 && errno == EFAULT)
			    ignore_err = recv(t->cli_fd, trash, sizeof(trash), MSG_NOSIGNAL);
		    }
		    goto terminate_client;
		}
		else { /* buffer not empty */
		    if (! FD_ISSET(t->cli_fd, StaticWriteEvent)) {
			FD_SET(t->cli_fd, StaticWriteEvent); /* restart writing */
			if (t->proxy->clitimeout) {
			    tv_delayfrom(&t->cwexpire, &now, t->proxy->clitimeout);
			    /* FIXME: to prevent the client from expiring read timeouts during writes,
			     * we refresh it. */
			    t->crexpire = t->cwexpire;
			}
			else
			    tv_eternity(&t->cwexpire);
		    }
		}
	    }
	}

	return 0; /* other cases change nothing */
    }
    else if (c == CL_STPAUSE) {
	if (!(t->sock_st & SKST_SCR) && (t->res_cr == RES_ERROR))
	    goto terminate_client;

	if (!(t->sock_st & SKST_SCR) && (t->res_cr == RES_NULL)) {
	    /* last read ? */
	    t->sock_st |= SKST_SCR;
	    if (t->sock_st & SKST_SCW)
		goto terminate_client;
	    FD_CLR(t->cli_fd, StaticReadEvent);
	    tv_eternity(&t->crexpire);
	    shutdown(t->cli_fd, SHUT_RD);
	}

	if (tv_cmp2_ms(&t->cnexpire, &now) > 0)
	    return 0; /* nothing changed */

	t->cli_state = CL_STDATA;
	tv_eternity(&t->cnexpire);

	/* Note: we also want to drain data */
	FD_SET(t->cli_fd, StaticWriteEvent);
	if (t->proxy->clitimeout)
	    tv_delayfrom(&t->cwexpire, &now, t->proxy->clitimeout);
	goto restart_data;
    }
    else { /* CL_STCLOSE: nothing to do */
	if ((global.mode & MODE_DEBUG) && (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))) {
	    int len;
	    len = sprintf(trash, "%08x:%s.clicls[%04x:%04x]\n", t->uniq_id, t->proxy->id, (unsigned short)t->cli_fd, (unsigned short)-1);
	    write(1, trash, len);
	}
	return 0;
    }
    return 0;
}


/* Processes the client and server jobs of a session task, then
 * puts it back to the wait queue in a clean state, or
 * cleans up its resources if it must be deleted. Returns
 * the time the task accepts to wait, or TIME_ETERNITY for
 * infinity.
 */
int process_session(struct task *t) {
    struct session *s = t->context;

    process_cli(s);

    if (s->cli_state != CL_STCLOSE) {
	struct timeval min1;
	s->res_cw = s->res_cr = RES_SILENT;

	tv_min(&min1, &s->crexpire, &s->cwexpire);
	tv_min(&t->expire, &min1, &s->cnexpire);

	/* restore t to its place in the task list */
	task_queue(t);

	return tv_remain2(&now, &t->expire); /* nothing more to do */
    }

    if (s->srv)
	s->srv->cur_sess--;

    s->proxy->nbconn--;
    actconn--;
    
    if ((global.mode & MODE_DEBUG) && (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))) {
	int len;
	len = sprintf(trash, "%08x:%s.closed[%04x:%04x]\n", s->uniq_id, s->proxy->id, (unsigned short)s->cli_fd, (unsigned short)-1);
	write(1, trash, len);
    }

    /* the task MUST not be in the run queue anymore */
    task_delete(t);
    session_free(s);
    task_free(t);
    return TIME_ETERNITY; /* rest in peace for eternity */
}



/*
 * This does 4 things :
 *   - wake up all expired tasks
 *   - call all runnable tasks
 *   - return the delay till next event in ms, -1 = wait indefinitely
 * Note: this part should be rewritten with the O(ln(n)) scheduler.
 *
 */

int process_runnable_tasks() {
  int next_time;
  struct task *t, *tnext;

  next_time = TIME_ETERNITY; /* set the timer to wait eternally first */

  /* look for expired tasks and add them to the run queue.
   */
  tnext = ((struct task *)LIST_HEAD(wait_queue[0]))->next;
  while ((t = tnext) != LIST_HEAD(wait_queue[0])) { /* we haven't looped ? */
      tnext = t->next;
      if (t->state & TASK_RUNNING)
	  continue;
      
      if (tv_iseternity(&t->expire))
	  continue;

      /* wakeup expired entries. It doesn't matter if they are
       * already running because of a previous event
       */
      if (tv_cmp_ms(&t->expire, &now) <= 0) {
	  task_wakeup(&rq, t);
      }
      else {
	  /* first non-runnable task. Use its expiration date as an upper bound */
	  int temp_time = tv_remain(&now, &t->expire);
	  if (temp_time)
	      next_time = temp_time;
	  break;
      }
  }

  /* process each task in the run queue now. Each task may be deleted
   * since we only use the run queue's head. Note that any task can be
   * woken up by any other task and it will be processed immediately
   * after as it will be queued on the run queue's head.
   */
  while ((t = rq) != NULL) {
      int temp_time;

      task_sleep(&rq, t);
      temp_time = t->process(t);
      next_time = MINTIME(temp_time, next_time);
  }
  return next_time;
}


#if defined(ENABLE_EPOLL)

/*
 * Main epoll() loop.
 */

/* does 3 actions :
 * 0 (POLL_LOOP_ACTION_INIT)  : initializes necessary private structures
 * 1 (POLL_LOOP_ACTION_RUN)   : runs the loop
 * 2 (POLL_LOOP_ACTION_CLEAN) : cleans up
 *
 * returns 0 if initialization failed, !0 otherwise.
 */

int epoll_loop(int action) {
  int next_time;
  int status;
  int fd;

  int fds, count;
  int pr, pw, sr, sw;
  unsigned rn, ro, wn, wo; /* read new, read old, write new, write old */
  struct epoll_event ev;

  /* private data */
  static struct epoll_event *epoll_events = NULL;
  static int epoll_fd;

  if (action == POLL_LOOP_ACTION_INIT) {
      epoll_fd = epoll_create(global.maxsock + 1);
      if (epoll_fd < 0)
	  return 0;
      else {
	  epoll_events = (struct epoll_event*)
	      calloc(1, sizeof(struct epoll_event) * global.maxsock);
	  PrevReadEvent = (fd_set *)
	      calloc(1, sizeof(fd_set) * (global.maxsock + FD_SETSIZE - 1) / FD_SETSIZE);
	  PrevWriteEvent = (fd_set *)
	      calloc(1, sizeof(fd_set) * (global.maxsock + FD_SETSIZE - 1) / FD_SETSIZE);
      }
      return 1;
  }
  else if (action == POLL_LOOP_ACTION_CLEAN) {
      if (PrevWriteEvent) free(PrevWriteEvent);
      if (PrevReadEvent)  free(PrevReadEvent);
      if (epoll_events)   free(epoll_events);
      close(epoll_fd);
      epoll_fd = 0;
      return 1;
  }

  /* OK, it's POLL_LOOP_ACTION_RUN */

  tv_now(&now);

  while (1) {
      next_time = process_runnable_tasks();

      /* stop when there's no connection left and we don't allow them anymore */
      if (!actconn && listeners == 0)
	  break;

      for (fds = 0; (fds << INTBITS) < maxfd; fds++) {
	  
	  rn = ((int*)StaticReadEvent)[fds];  ro = ((int*)PrevReadEvent)[fds];
	  wn = ((int*)StaticWriteEvent)[fds]; wo = ((int*)PrevWriteEvent)[fds];
	  
	  if ((ro^rn) | (wo^wn)) {
	      for (count = 0, fd = fds << INTBITS; count < (1<<INTBITS) && fd < maxfd; count++, fd++) {
#define FDSETS_ARE_INT_ALIGNED
#ifdef FDSETS_ARE_INT_ALIGNED

#define WE_REALLY_NOW_THAT_FDSETS_ARE_INTS
#ifdef WE_REALLY_NOW_THAT_FDSETS_ARE_INTS
		  pr = (ro >> count) & 1;
		  pw = (wo >> count) & 1;
		  sr = (rn >> count) & 1;
		  sw = (wn >> count) & 1;
#else
		  pr = FD_ISSET(fd&((1<<INTBITS)-1), (typeof(fd_set*))&ro);
		  pw = FD_ISSET(fd&((1<<INTBITS)-1), (typeof(fd_set*))&wo);
		  sr = FD_ISSET(fd&((1<<INTBITS)-1), (typeof(fd_set*))&rn);
		  sw = FD_ISSET(fd&((1<<INTBITS)-1), (typeof(fd_set*))&wn);
#endif
#else
		  pr = FD_ISSET(fd, PrevReadEvent);
		  pw = FD_ISSET(fd, PrevWriteEvent);
		  sr = FD_ISSET(fd, StaticReadEvent);
		  sw = FD_ISSET(fd, StaticWriteEvent);
#endif
		  if (!((sr^pr) | (sw^pw)))
		      continue;

		  ev.events = (sr ? EPOLLIN : 0) | (sw ? EPOLLOUT : 0);
		  ev.data.fd = fd;

#ifdef EPOLL_CTL_MOD_WORKAROUND
		  /* I encountered a rarely reproducible problem with
		   * EPOLL_CTL_MOD where a modified FD (systematically
		   * the one in epoll_events[0], fd#7) would sometimes
		   * be set EPOLL_OUT while asked for a read ! This is
		   * with the 2.4 epoll patch. The workaround is to
		   * delete then recreate in case of modification.
		   * This is in 2.4 up to epoll-lt-0.21 but not in 2.6
		   * nor RHEL kernels.
		   */

		  if ((pr | pw) && fdtab[fd].state != FD_STCLOSE)
		      epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, &ev);

		  if ((sr | sw))
		      epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev);
#else
		  if ((pr | pw)) {
		      /* the file-descriptor already exists... */
		      if ((sr | sw)) {
			  /* ...and it will still exist */
			  if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev) < 0) {
			      // perror("epoll_ctl(MOD)");
			      // exit(1);
			  }
		      } else {
			  /* ...and it will be removed */
			  if (fdtab[fd].state != FD_STCLOSE &&
			      epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, &ev) < 0) {
			      // perror("epoll_ctl(DEL)");
			      // exit(1);
			  }
		      }
		  } else {
		      /* the file-descriptor did not exist, let's add it */
		      if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
			  // perror("epoll_ctl(ADD)");
			  //  exit(1);
		      }
		  }
#endif // EPOLL_CTL_MOD_WORKAROUND
	      }
	      ((int*)PrevReadEvent)[fds] = rn;
	      ((int*)PrevWriteEvent)[fds] = wn;
	  }		  
      }
      
      /* now let's wait for events */
      status = epoll_wait(epoll_fd, epoll_events, maxfd, next_time);
      tv_now(&now);

      for (count = 0; count < status; count++) {
	  fd = epoll_events[count].data.fd;

	  if (FD_ISSET(fd, StaticReadEvent)) {
		  if (fdtab[fd].state == FD_STCLOSE)
			  continue;
		  if (epoll_events[count].events & ( EPOLLIN | EPOLLERR | EPOLLHUP ))
			  fdtab[fd].read(fd);
	  }

	  if (FD_ISSET(fd, StaticWriteEvent)) {
		  if (fdtab[fd].state == FD_STCLOSE)
			  continue;
		  if (epoll_events[count].events & ( EPOLLOUT | EPOLLERR | EPOLLHUP ))
			  fdtab[fd].write(fd);
	  }
      }
  }
  return 1;
}
#endif


#if defined(ENABLE_POLL)

/*
 * Main poll() loop.
 */

/* does 3 actions :
 * 0 (POLL_LOOP_ACTION_INIT)  : initializes necessary private structures
 * 1 (POLL_LOOP_ACTION_RUN)   : runs the loop
 * 2 (POLL_LOOP_ACTION_CLEAN) : cleans up
 *
 * returns 0 if initialization failed, !0 otherwise.
 */

int poll_loop(int action) {
  int next_time;
  int status;
  int fd, nbfd;

  int fds, count;
  int sr, sw;
  unsigned rn, wn; /* read new, write new */

  /* private data */
  static struct pollfd *poll_events = NULL;

  if (action == POLL_LOOP_ACTION_INIT) {
      poll_events = (struct pollfd*)
	  calloc(1, sizeof(struct pollfd) * global.maxsock);
      return 1;
  }
  else if (action == POLL_LOOP_ACTION_CLEAN) {
      if (poll_events)
	  free(poll_events);
      return 1;
  }

  /* OK, it's POLL_LOOP_ACTION_RUN */

  tv_now(&now);

  while (1) {
      next_time = process_runnable_tasks();

      /* stop when there's no connection left and we don't allow them anymore */
      if (!actconn && listeners == 0)
	  break;

      nbfd = 0;
      for (fds = 0; (fds << INTBITS) < maxfd; fds++) {
	  
	  rn = ((int*)StaticReadEvent)[fds];
	  wn = ((int*)StaticWriteEvent)[fds];
	  
	  if ((rn|wn)) {
	      for (count = 0, fd = fds << INTBITS; count < (1<<INTBITS) && fd < maxfd; count++, fd++) {
#define FDSETS_ARE_INT_ALIGNED
#ifdef FDSETS_ARE_INT_ALIGNED

#define WE_REALLY_NOW_THAT_FDSETS_ARE_INTS
#ifdef WE_REALLY_NOW_THAT_FDSETS_ARE_INTS
		  sr = (rn >> count) & 1;
		  sw = (wn >> count) & 1;
#else
		  sr = FD_ISSET(fd&((1<<INTBITS)-1), (typeof(fd_set*))&rn);
		  sw = FD_ISSET(fd&((1<<INTBITS)-1), (typeof(fd_set*))&wn);
#endif
#else
		  sr = FD_ISSET(fd, StaticReadEvent);
		  sw = FD_ISSET(fd, StaticWriteEvent);
#endif
		  if ((sr|sw)) {
		      poll_events[nbfd].fd = fd;
		      poll_events[nbfd].events = (sr ? POLLIN : 0) | (sw ? POLLOUT : 0);
		      nbfd++;
		  }
	      }
	  }		  
      }
      
      /* now let's wait for events */
      status = poll(poll_events, nbfd, next_time);
      tv_now(&now);

      for (count = 0; status > 0 && count < nbfd; count++) {
	  fd = poll_events[count].fd;
	  
	  if (!(poll_events[count].revents & ( POLLOUT | POLLIN | POLLERR | POLLHUP )))
	      continue;

	  /* ok, we found one active fd */
	  status--;

	  if (FD_ISSET(fd, StaticReadEvent)) {
		  if (fdtab[fd].state == FD_STCLOSE)
			  continue;
		  if (poll_events[count].revents & ( POLLIN | POLLERR | POLLHUP ))
			  fdtab[fd].read(fd);
	  }
	  
	  if (FD_ISSET(fd, StaticWriteEvent)) {
		  if (fdtab[fd].state == FD_STCLOSE)
			  continue;
		  if (poll_events[count].revents & ( POLLOUT | POLLERR | POLLHUP ))
			  fdtab[fd].write(fd);
	  }
      }
  }
  return 1;
}
#endif



/*
 * Main select() loop.
 */

/* does 3 actions :
 * 0 (POLL_LOOP_ACTION_INIT)  : initializes necessary private structures
 * 1 (POLL_LOOP_ACTION_RUN)   : runs the loop
 * 2 (POLL_LOOP_ACTION_CLEAN) : cleans up
 *
 * returns 0 if initialization failed, !0 otherwise.
 */


int select_loop(int action) {
  int next_time;
  int status;
  int fd,i;
  struct timeval delta;
  int readnotnull, writenotnull;
  static fd_set	*ReadEvent = NULL, *WriteEvent = NULL;

  if (action == POLL_LOOP_ACTION_INIT) {
      ReadEvent = (fd_set *)
	  calloc(1, sizeof(fd_set) * (global.maxsock + FD_SETSIZE - 1) / FD_SETSIZE);
      WriteEvent = (fd_set *)
	  calloc(1, sizeof(fd_set) * (global.maxsock + FD_SETSIZE - 1) / FD_SETSIZE);
      return 1;
  }
  else if (action == POLL_LOOP_ACTION_CLEAN) {
      if (WriteEvent)       free(WriteEvent);
      if (ReadEvent)        free(ReadEvent);
      return 1;
  }

  /* OK, it's POLL_LOOP_ACTION_RUN */

  tv_now(&now);

  while (1) {
      next_time = process_runnable_tasks();

      /* stop when there's no connection left and we don't allow them anymore */
      if (!actconn && listeners == 0)
	  break;

      if (next_time > 0) {  /* FIXME */
	  /* Convert to timeval */
	  /* to avoid eventual select loops due to timer precision */
	  next_time += SCHEDULER_RESOLUTION;
	  delta.tv_sec  = next_time / 1000; 
	  delta.tv_usec = (next_time % 1000) * 1000;
      }
      else if (next_time == 0) { /* allow select to return immediately when needed */
	  delta.tv_sec = delta.tv_usec = 0;
      }


      /* let's restore fdset state */

      readnotnull = 0; writenotnull = 0;
      for (i = 0; i < (maxfd + FD_SETSIZE - 1)/(8*sizeof(int)); i++) {
	  readnotnull |= (*(((int*)ReadEvent)+i) = *(((int*)StaticReadEvent)+i)) != 0;
	  writenotnull |= (*(((int*)WriteEvent)+i) = *(((int*)StaticWriteEvent)+i)) != 0;
      }

      //	/* just a verification code, needs to be removed for performance */
      //	for (i=0; i<maxfd; i++) {
      //	    if (FD_ISSET(i, ReadEvent) != FD_ISSET(i, StaticReadEvent))
      //		abort();
      //	    if (FD_ISSET(i, WriteEvent) != FD_ISSET(i, StaticWriteEvent))
      //		abort();
      //	    
      //	}

      status = select(maxfd,
		      readnotnull ? ReadEvent : NULL,
		      writenotnull ? WriteEvent : NULL,
		      NULL,
		      (next_time >= 0) ? &delta : NULL);
      
      /* this is an experiment on the separation of the select work */
      // status  = (readnotnull  ? select(maxfd, ReadEvent, NULL, NULL, (next_time >= 0) ? &delta : NULL) : 0);
      // status |= (writenotnull ? select(maxfd, NULL, WriteEvent, NULL, (next_time >= 0) ? &delta : NULL) : 0);
      
      tv_now(&now);

      if (status > 0) { /* must proceed with events */

	  int fds;
	  char count;
	  
	  for (fds = 0; (fds << INTBITS) < maxfd; fds++)
	      if ((((int *)(ReadEvent))[fds] | ((int *)(WriteEvent))[fds]) != 0)
		  for (count = 1<<INTBITS, fd = fds << INTBITS; count && fd < maxfd; count--, fd++) {
		      
		      /* if we specify read first, the accepts and zero reads will be
		       * seen first. Moreover, system buffers will be flushed faster.
		       */
			  if (FD_ISSET(fd, ReadEvent)) {
				  if (fdtab[fd].state == FD_STCLOSE)
					  continue;
				  fdtab[fd].read(fd);
			  }

			  if (FD_ISSET(fd, WriteEvent)) {
				  if (fdtab[fd].state == FD_STCLOSE)
					  continue;
				  fdtab[fd].write(fd);
			  }
		  }
      }
      else {
	  //	  fprintf(stderr,"select returned %d, maxfd=%d\n", status, maxfd);
      }
  }
  return 1;
}

/*
 * this function dumps every server's state when the process receives SIGHUP.
 */
void sig_dump_state(int sig) {
    struct proxy *p = proxy;

    Warning("SIGHUP received, dumping servers states.\n");
    while (p) {
	struct server *s = p->srv;

	while (s) {
	    snprintf(trash, sizeof(trash),
		     "SIGHUP: Server %s/%s : Conn: %d act, %d pend, %d tot.",
		     p->id, s->id,
		     s->cur_sess, 0, s->cum_sess);
	    Warning("%s\n", trash);
	    s = s->next;
	}

	snprintf(trash, sizeof(trash),
		 "SIGHUP: Proxy %s has %d active servers available."
		 " Conn: %d act, %d pend (%d unass), %d tot.",
		 p->id, p->srv_act, 
		 p->nbconn, 0, 0, p->cum_conn);
	Warning("%s\n", trash);
	p = p->next;
    }
    signal(sig, sig_dump_state);
}

/*
 * parse a line in a <global> section. Returns 0 if OK, -1 if error.
 */
int cfg_parse_global(char *file, int linenum, char **args) {

    if (!strcmp(args[0], "global")) {  /* new section */
	/* no option, nothing special to do */
	return 0;
    }
    else if (!strcmp(args[0], "daemon")) {
	global.mode |= MODE_DAEMON;
    }
    else if (!strcmp(args[0], "debug")) {
	global.mode |= MODE_DEBUG;
    }
    else if (!strcmp(args[0], "sendzero")) {
	global.flags |= GFLAGS_SEND_ZERO;
    }
    else if (!strcmp(args[0], "nosplice")) {
	global.flags |= GFLAGS_NO_SPLICE;
    }
    else if (!strcmp(args[0], "noepoll")) {
	cfg_polling_mechanism &= ~POLL_USE_EPOLL;
    }
    else if (!strcmp(args[0], "nopoll")) {
	cfg_polling_mechanism &= ~POLL_USE_POLL;
    }
    else if (!strcmp(args[0], "quiet")) {
	global.mode |= MODE_QUIET;
    }
    else if (!strcmp(args[0], "uid")) {
	if (global.uid != 0) {
	    Alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
	    return 0;
	}
	if (*(args[1]) == 0) {
	    Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
	    return -1;
	}
	global.uid = atol(args[1]);
    }
    else if (!strcmp(args[0], "gid")) {
	if (global.gid != 0) {
	    Alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
	    return 0;
	}
	if (*(args[1]) == 0) {
	    Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
	    return -1;
	}
	global.gid = atol(args[1]);
    }
    else if (!strcmp(args[0], "nbproc")) {
	if (global.nbproc != 0) {
	    Alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
	    return 0;
	}
	if (*(args[1]) == 0) {
	    Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
	    return -1;
	}
	global.nbproc = atol(args[1]);
    }
    else if (!strcmp(args[0], "maxconn")) {
	if (global.maxconn != 0) {
	    Alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
	    return 0;
	}
	if (*(args[1]) == 0) {
	    Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
	    return -1;
	}
	global.maxconn = atol(args[1]);
#ifdef SYSTEM_MAXCONN
	if (global.maxconn > DEFAULT_MAXCONN && cfg_maxconn <= DEFAULT_MAXCONN) {
	    Alert("parsing [%s:%d] : maxconn value %d too high for this system.\nLimiting to %d. Please use '-n' to force the value.\n", file, linenum, global.maxconn, DEFAULT_MAXCONN);
	    global.maxconn = DEFAULT_MAXCONN;
	}
#endif /* SYSTEM_MAXCONN */
	/* we want to update the default instance's maxconn too */
	if (!cfg_maxconn)
	    defproxy.maxconn = global.maxconn;
    }
    else if (!strcmp(args[0], "ulimit-n")) {
	if (global.rlimit_nofile != 0) {
	    Alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
	    return 0;
	}
	if (*(args[1]) == 0) {
	    Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
	    return -1;
	}
	global.rlimit_nofile = atol(args[1]);
    }
    else if (!strcmp(args[0], "chroot")) {
	if (global.chroot != NULL) {
	    Alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
	    return 0;
	}
	if (*(args[1]) == 0) {
	    Alert("parsing [%s:%d] : '%s' expects a directory as an argument.\n", file, linenum, args[0]);
	    return -1;
	}
	global.chroot = strdup(args[1]);
    }
    else if (!strcmp(args[0], "pidfile")) {
	if (global.pidfile != NULL) {
	    Alert("parsing [%s:%d] : '%s' already specified. Continuing.\n", file, linenum, args[0]);
	    return 0;
	}
	if (*(args[1]) == 0) {
	    Alert("parsing [%s:%d] : '%s' expects a file name as an argument.\n", file, linenum, args[0]);
	    return -1;
	}
	global.pidfile = strdup(args[1]);
    }
    else if (!strcmp(args[0], "pipesize")) {
	if (*(args[1]) == 0) {
	    Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
	    return -1;
	}
	pipesize = atol(args[1]);
    }
    else {
	Alert("parsing [%s:%d] : unknown keyword '%s' in '%s' section\n", file, linenum, args[0], "global");
	return -1;
    }
    return 0;
}


void init_default_instance() {
    memset(&defproxy, 0, sizeof(defproxy));
    defproxy.state = PR_STNEW;
    defproxy.maxconn = cfg_maxconn ? cfg_maxconn : global.maxconn;
    if (!defproxy.maxconn)
	defproxy.maxconn = DEFAULT_MAXCONN;
}

/*
 * parse a line in a <listen> section. Returns 0 if OK, -1 if error.
 */
int cfg_parse_listen(const char *file, int linenum, char **args) {
    static struct proxy *curproxy = NULL;
    struct server *newsrv = NULL;

    if (!strcmp(args[0], "listen")) {  /* new proxy */
	if (!*args[1]) {
	    Alert("parsing [%s:%d] : '%s' expects an <id> argument and\n"
		  "  optionnally supports [addr1]:port1[-end1]{,[addr]:port[-end]}...\n",
		  file, linenum, args[0]);
	    return -1;
	}
	
	if ((curproxy = (struct proxy *)calloc(1, sizeof(struct proxy))) == NULL) {
	    Alert("parsing [%s:%d] : out of memory.\n", file, linenum);
	    return -1;
	}
	
	curproxy->next = proxy;
	proxy = curproxy;

	curproxy->id = strdup(args[1]);

	/* parse the listener address if any */
	if (*args[2]) {
	    curproxy->listen = str2listener(args[2], curproxy->listen);
	    if (!curproxy->listen)
		return -1;
	    global.maxsock++;
	}

	/* set default values */
	curproxy->state = defproxy.state;
	curproxy->maxconn = defproxy.maxconn;
	curproxy->options = defproxy.options;

	if (defproxy.errmsg.msg400)
	    curproxy->errmsg.msg400 = strdup(defproxy.errmsg.msg400);
	curproxy->errmsg.len400 = defproxy.errmsg.len400;

	if (defproxy.errmsg.msg403)
	    curproxy->errmsg.msg403 = strdup(defproxy.errmsg.msg403);
	curproxy->errmsg.len403 = defproxy.errmsg.len403;

	if (defproxy.errmsg.msg408)
	    curproxy->errmsg.msg408 = strdup(defproxy.errmsg.msg408);
	curproxy->errmsg.len408 = defproxy.errmsg.len408;

	if (defproxy.errmsg.msg500)
	    curproxy->errmsg.msg500 = strdup(defproxy.errmsg.msg500);
	curproxy->errmsg.len500 = defproxy.errmsg.len500;

	if (defproxy.errmsg.msg502)
	    curproxy->errmsg.msg502 = strdup(defproxy.errmsg.msg502);
	curproxy->errmsg.len502 = defproxy.errmsg.len502;

	if (defproxy.errmsg.msg503)
	    curproxy->errmsg.msg503 = strdup(defproxy.errmsg.msg503);
	curproxy->errmsg.len503 = defproxy.errmsg.len503;

	if (defproxy.errmsg.msg504)
	    curproxy->errmsg.msg504 = strdup(defproxy.errmsg.msg504);
	curproxy->errmsg.len504 = defproxy.errmsg.len504;

	curproxy->clitimeout = defproxy.clitimeout;
	curproxy->grace  = defproxy.grace;
	return 0;
    }
    else if (!strcmp(args[0], "defaults")) {  /* use this one to assign default values */
	/* some variables may have already been initialized earlier */
	if (defproxy.errmsg.msg400) free(defproxy.errmsg.msg400);
	if (defproxy.errmsg.msg403) free(defproxy.errmsg.msg403);
	if (defproxy.errmsg.msg408) free(defproxy.errmsg.msg408);
	if (defproxy.errmsg.msg500) free(defproxy.errmsg.msg500);
	if (defproxy.errmsg.msg502) free(defproxy.errmsg.msg502);
	if (defproxy.errmsg.msg503) free(defproxy.errmsg.msg503);
	if (defproxy.errmsg.msg504) free(defproxy.errmsg.msg504);

	init_default_instance();
	curproxy = &defproxy;
	return 0;
    }
    else if (curproxy == NULL) {
	Alert("parsing [%s:%d] : 'listen' or 'defaults' expected.\n", file, linenum);
	return -1;
    }

    /* ignore disabled listeners so that we don't fail on missing files */
    if (curproxy->state == PR_STSTOPPED)
	return 0;

    if (!strcmp(args[0], "bind")) {  /* new listen addresses */
	if (curproxy == &defproxy) {
	    Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
	    return -1;
	}

	if (strchr(args[1], ':') == NULL) {
	    Alert("parsing [%s:%d] : '%s' expects [addr1]:port1[-end1]{,[addr]:port[-end]}... as arguments.\n",
		  file, linenum, args[0]);
	    return -1;
	}
	curproxy->listen = str2listener(args[1], curproxy->listen);
	if (!curproxy->listen)
	    return -1;
	global.maxsock++;
	return 0;
    }
    else if (!strcmp(args[0], "disabled")) {  /* disables this proxy */
	curproxy->state = PR_STSTOPPED;
    }
    else if (!strcmp(args[0], "enabled")) {  /* enables this proxy (used to revert a disabled default) */
	curproxy->state = PR_STNEW;
    }
    else if (!strcmp(args[0], "clitimeout")) {  /*  client timeout */
	if (curproxy->clitimeout != defproxy.clitimeout) {
	    Alert("parsing [%s:%d] : '%s' already specified. Continuing.\n",
		  file, linenum, args[0]);
	    return 0;
	}
	if (*(args[1]) == 0) {
	    Alert("parsing [%s:%d] : '%s' expects an integer <time_in_ms> as argument.\n",
		  file, linenum, args[0]);
	    return -1;
	}
	curproxy->clitimeout = atol(args[1]);
    }
    else if (!strcmp(args[0], "option")) {
	if (*(args[1]) == 0) {
	    Alert("parsing [%s:%d] : '%s' expects an option name.\n", file, linenum, args[0]);
	    return -1;
	}
	if (!strcmp(args[1], "httpclose"))
	    /* force connection: close in both directions in HTTP mode */
	    curproxy->options |= PR_O_HTTP_CLOSE;
	else if (!strcmp(args[1], "forceclose"))
	    /* force connection: close in both directions in HTTP mode and enforce end of session */
	    curproxy->options |= PR_O_FORCE_CLO | PR_O_HTTP_CLOSE;
	else if (!strcmp(args[1], "tcpka")) {
	    /* enable TCP keep-alives on client and server sessions */
	    curproxy->options |= PR_O_TCP_CLI_KA;
	}
	else if (!strcmp(args[1], "clitcpka")) {
	    /* enable TCP keep-alives on client sessions */
	    curproxy->options |= PR_O_TCP_CLI_KA;
	}
	else {
	    Alert("parsing [%s:%d] : unknown option '%s'.\n", file, linenum, args[1]);
	    return -1;
	}
	return 0;
    }
    else if (!strcmp(args[0], "maxconn")) {  /* maxconn */
	if (*(args[1]) == 0) {
	    Alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
	    return -1;
	}
	curproxy->maxconn = atol(args[1]);
    }
    else if (!strcmp(args[0], "grace")) {  /* grace time (ms) */
	if (*(args[1]) == 0) {
	    Alert("parsing [%s:%d] : '%s' expects a time in milliseconds.\n", file, linenum, args[0]);
	    return -1;
	}
	curproxy->grace = atol(args[1]);
    }
    else if (!strcmp(args[0], "object")) {
	int cur_arg;

	if (curproxy == &defproxy) {
	    Alert("parsing [%s:%d] : '%s' not allowed in 'defaults' section.\n", file, linenum, args[0]);
	    return -1;
	}

	if (!*args[2]) {
	    Alert("parsing [%s:%d] : '%s' expects <name> as arguments.\n",
		  file, linenum, args[0]);
	    return -1;
	}
	if ((newsrv = (struct server *)calloc(1, sizeof(struct server))) == NULL) {
	    Alert("parsing [%s:%d] : out of memory.\n", file, linenum);
	    return -1;
	}

	/* the servers are linked backwards first */
	newsrv->next = curproxy->srv;
	curproxy->srv = newsrv;
	newsrv->proxy = curproxy;

	newsrv->resp_cache = 1;
	newsrv->resp_code = 200;
	newsrv->resp_size = -1; /* not yet set */

	cur_arg = 1;
	while (*args[cur_arg]) {
	    if (!strcmp(args[cur_arg], "name")) {
		newsrv->id = strdup(args[cur_arg + 1]);
		cur_arg += 2;
	    }
	    else if (!strcmp(args[cur_arg], "cache")) {
		newsrv->resp_cache = 1;
		cur_arg += 1;
	    }
	    else if (!strcmp(args[cur_arg], "no-cache")) {
		newsrv->resp_cache = 0;
		cur_arg += 1;
	    }
	    else if (!strcmp(args[cur_arg], "code")) {
		newsrv->resp_code = atol(args[cur_arg + 1]);
		cur_arg += 2;
	    }
	    else if (!strcmp(args[cur_arg], "size")) {
		newsrv->resp_size = atol(args[cur_arg + 1]);
		cur_arg += 2;
	    }
	    else if (!strcmp(args[cur_arg], "time")) {
		newsrv->resp_time = atol(args[cur_arg + 1]);
		cur_arg += 2;
	    }
	    else if (!strcmp(args[cur_arg], "file")) {
		int ret, hdr, fd;
		char *buf;
		struct stat stat;

		if (*(args[1]) == 0) {
		    Alert("parsing [%s:%d] : <%s> expects a <file> argument.\n", file, linenum, args[0]);
			return -1;
		}

		fd = open(args[cur_arg + 1], O_RDONLY);
		if ((fd < 0) || (fstat(fd, &stat) < 0)) {
			Alert("parsing [%s:%d] : error opening file <%s>.\n",
			      file, linenum, args[cur_arg + 1]);
			if (fd >= 0)
				close(fd);
			return -1;
		}

		if (newsrv->resp_size < 0 || newsrv->resp_size > stat.st_size)
		    newsrv->resp_size = stat.st_size;

		hdr = sprintf(trash,
			       "HTTP/1.1 %03d\r\n"
			       "Connection: close\r\n"
			       "Content-length: %d\r\n"
			       "%s"
			       "X-req: size=%d, time=%d ms\r\n"
			       "X-rsp: id=%s, code=%d, cache=%d, size=%d, time=%d ms\r\n"
			       "\r\n",
			       newsrv->resp_code,
			       newsrv->resp_size,
			       newsrv->resp_cache ? "" : "Cache-Control: no-cache\r\n",
			       newsrv->resp_size, newsrv->resp_time, 
			       newsrv->id, newsrv->resp_code, newsrv->resp_cache,
			       newsrv->resp_size, newsrv->resp_time);

		buf = malloc(hdr + newsrv->resp_size); /* malloc() must succeed during parsing */
		if (!buf) {
			Alert("parsing [%s:%d] : not enough memory to read file <%s>.\n",
			      file, linenum, args[cur_arg + 1]);
			close(fd);
			return -1;
		}

		memcpy(buf, trash, hdr);
		ret = read(fd, buf + hdr, newsrv->resp_size);
		close(fd);
		if (ret != newsrv->resp_size) {
			Alert("parsing [%s:%d] : error reading file <%s>.\n",
			      file, linenum, args[cur_arg + 1]);
			free(buf);
			return -1;
		}

		newsrv->resp_size += hdr;
		newsrv->resp_data = buf;
		cur_arg += 2;
	    }
	    else if (!strcmp(args[cur_arg], "rawfile")) {
		int ret, fd;
		char *buf;
		struct stat stat;

		if (*(args[1]) == 0) {
		    Alert("parsing [%s:%d] : <%s> expects a <file> argument.\n", file, linenum, args[0]);
			return -1;
		}

		fd = open(args[cur_arg + 1], O_RDONLY);
		if ((fd < 0) || (fstat(fd, &stat) < 0)) {
			Alert("parsing [%s:%d] : error opening file <%s>.\n",
			      file, linenum, args[cur_arg + 1]);
			if (fd >= 0)
				close(fd);
			return -1;
		}

		if (newsrv->resp_size < 0 || newsrv->resp_size > stat.st_size)
		    newsrv->resp_size = stat.st_size;

		buf = malloc(newsrv->resp_size); /* malloc() must succeed during parsing */
		if (!buf) {
			Alert("parsing [%s:%d] : not enough memory to read file <%s>.\n",
			      file, linenum, args[cur_arg + 1]);
			close(fd);
			return -1;
		}

		ret = read(fd, buf, newsrv->resp_size);
		close(fd);
		if (ret != newsrv->resp_size) {
			Alert("parsing [%s:%d] : error reading file <%s>.\n",
			      file, linenum, args[cur_arg + 1]);
			free(buf);
			return -1;
		}

		newsrv->resp_data = buf;
		cur_arg += 2;
	    }
	    else if (!strcmp(args[cur_arg], "weight")) {
		int w;
		w = atol(args[cur_arg + 1]);
		if (w < 1 || w > 256) {
		    Alert("parsing [%s:%d] : weight of object %s is not within 1 and 256 (%d).\n",
			  file, linenum, newsrv->id, w);
		    return -1;
		}
		newsrv->uweight = w - 1;
		cur_arg += 2;
	    }
	    else {
		Alert("parsing [%s:%d] : object %s only supports options 'name', 'code', 'size', 'time', 'cache', 'no-cache', 'file', 'rawfile' and 'weight'.\n",
		      file, linenum, newsrv->id);
		return -1;
	    }
	}
    }
    else {
	Alert("parsing [%s:%d] : unknown keyword '%s' in '%s' section\n", file, linenum, args[0], "listen");
	return -1;
    }
    return 0;
}


/*
 * This function reads and parses the configuration file given in the argument.
 * returns 0 if OK, -1 if error. If the file is NULL, it is ignored.
 */
int readcfgfile(char *file) {
    char thisline[256];
    char *line;
    FILE *f = NULL;
    int linenum = 0;
    char *end;
    char *args[MAX_LINE_ARGS];
    int arg;
    int cfgerr = 0;
    int confsect = CFG_NONE;

    struct proxy *curproxy = NULL;
    struct server *newsrv = NULL;

    if (file && (f=fopen(file,"r")) == NULL)
	return -1;

    init_default_instance();

    while (f && fgets(line = thisline, sizeof(thisline), f) != NULL) {
	linenum++;

	end = line + strlen(line);

	/* skip leading spaces */
	while (isspace((int)*line))
	    line++;
	
	arg = 0;
	args[arg] = line;

	while (*line && arg < MAX_LINE_ARGS) {
	    /* first, we'll replace \\, \<space>, \#, \r, \n, \t, \xXX with their
	     * C equivalent value. Other combinations left unchanged (eg: \1).
	     */
	    if (*line == '\\') {
		int skip = 0;
		if (line[1] == ' ' || line[1] == '\\' || line[1] == '#') {
		    *line = line[1];
		    skip = 1;
		}
		else if (line[1] == 'r') {
		    *line = '\r';
		    skip = 1;
		} 
		else if (line[1] == 'n') {
		    *line = '\n';
		    skip = 1;
		}
		else if (line[1] == 't') {
		    *line = '\t';
		    skip = 1;
		}
		else if (line[1] == 'x') {
		    if ((line + 3 < end ) && ishex(line[2]) && ishex(line[3])) {
			unsigned char hex1, hex2;
			hex1 = toupper(line[2]) - '0';
			hex2 = toupper(line[3]) - '0';
			if (hex1 > 9) hex1 -= 'A' - '9' - 1;
			if (hex2 > 9) hex2 -= 'A' - '9' - 1;
			*line = (hex1<<4) + hex2;
			skip = 3;
		    }
		    else {
			Alert("parsing [%s:%d] : invalid or incomplete '\\x' sequence in '%s'.\n", file, linenum, args[0]);
			return -1;
		    }
		}
		if (skip) {
		    memmove(line + 1, line + 1 + skip, end - (line + skip + 1));
		    end -= skip;
		}
		line++;
	    }
	    else if (*line == '#' || *line == '\n' || *line == '\r') {
		/* end of string, end of loop */
		*line = 0;
		break;
	    }
	    else if (isspace((int)*line)) {
		/* a non-escaped space is an argument separator */
		*line++ = 0;
		while (isspace((int)*line))
		    line++;
		args[++arg] = line;
	    }
	    else {
		line++;
	    }
	}

	/* empty line */
	if (!**args)
	    continue;

	/* zero out remaining args */
	while (++arg < MAX_LINE_ARGS) {
	    args[arg] = line;
	}

	if (!strcmp(args[0], "listen") || !strcmp(args[0], "defaults"))  /* new proxy */
	    confsect = CFG_LISTEN;
	else if (!strcmp(args[0], "global"))  /* global config */
	    confsect = CFG_GLOBAL;
	/* else it's a section keyword */

	switch (confsect) {
	case CFG_LISTEN:
	    if (cfg_parse_listen(file, linenum, args) < 0)
		return -1;
	    break;
	case CFG_GLOBAL:
	    if (cfg_parse_global(file, linenum, args) < 0)
		return -1;
	    break;
	default:
	    Alert("parsing [%s:%d] : unknown keyword '%s' out of section.\n", file, linenum, args[0]);
	    return -1;
	}
	    
	    
    }
    if (f)
	fclose(f);

    /* Maybe the user has specified a listener on the command line */
    if (cmdline_listen) {
	const char *name = "command line";
	args[0] = "listen";
	args[1] = "dummy";
	args[2] = "\0";
	if (cfg_parse_listen(name, 0, args) < 0)
	    return -1;

	args[0] = "bind";
	args[1] = cmdline_listen;
	args[2] = "\0";
	if (cfg_parse_listen(name, 0, args) < 0)
	    return -1;

	args[0] = "object";
	args[1] = "name";
	args[2] = "dummy";
	args[3] = "\0";
	if (cfg_parse_listen(name, 0, args) < 0)
	    return -1;

	args[0] = "clitimeout";
	args[1] = "10000";
	args[2] = "\0";
	if (cfg_parse_listen(name, 0, args) < 0)
	    return -1;
    }

    /*
     * Now, check for the integrity of all that we have collected.
     */

    /* will be needed further to delay some tasks */
    tv_now(&now);

    if ((curproxy = proxy) == NULL) {
	Alert("parsing %s : no <listen> line. Nothing to do !\n",
	      file);
	return -1;
    }

    while (curproxy != NULL) {
	if (curproxy->state == PR_STSTOPPED) {
	    curproxy = curproxy->next;
	    continue;
	}

	if (curproxy->listen == NULL) {
	    Alert("parsing %s : listener %s has no listen address. Please either specify a valid address on the <listen> line, or use the <bind> keyword.\n", file, curproxy->id);
	    cfgerr++;
	}

	/* first, we will invert the servers list order */
	newsrv = NULL;
	while (curproxy->srv) {
	    struct server *next;

	    next = curproxy->srv->next;
	    curproxy->srv->next = newsrv;
	    newsrv = curproxy->srv;
	    if (!next)
		break;
	    curproxy->srv = next;
	}

	/* now, newsrv == curproxy->srv */
	if (newsrv) {
	    struct server *srv;
	    int pgcd;
	    int act;

	    /* We will factor the weights to reduce the table,
	     * using Euclide's largest common divisor algorithm
	     */
	    pgcd = newsrv->uweight + 1;
	    for (srv = newsrv->next; srv && pgcd > 1; srv = srv->next) {
		int t, w;
		
		w = srv->uweight + 1;
		while (w) {
		    t = pgcd % w;
		    pgcd = w;
		    w = t;
		}
	    }

	    act = 0;
	    for (srv = newsrv; srv; srv = srv->next) {
		srv->eweight = ((srv->uweight + 1) / pgcd) - 1;
		act += srv->eweight + 1;
	    }

	    curproxy->srv_map = (struct server **)calloc(act, sizeof(struct server *));
	    /* recounts servers and their weights */
	    recount_servers(curproxy);
	    recalc_server_map(curproxy);
	}

	if (curproxy->errmsg.msg400 == NULL) {
	    curproxy->errmsg.msg400 = (char *)HTTP_400;
	    curproxy->errmsg.len400 = strlen(HTTP_400);
	}
	if (curproxy->errmsg.msg403 == NULL) {
	    curproxy->errmsg.msg403 = (char *)HTTP_403;
	    curproxy->errmsg.len403 = strlen(HTTP_403);
	}
	if (curproxy->errmsg.msg408 == NULL) {
	    curproxy->errmsg.msg408 = (char *)HTTP_408;
	    curproxy->errmsg.len408 = strlen(HTTP_408);
	}
	if (curproxy->errmsg.msg500 == NULL) {
	    curproxy->errmsg.msg500 = (char *)HTTP_500;
	    curproxy->errmsg.len500 = strlen(HTTP_500);
	}
	if (curproxy->errmsg.msg502 == NULL) {
	    curproxy->errmsg.msg502 = (char *)HTTP_502;
	    curproxy->errmsg.len502 = strlen(HTTP_502);
	}
	if (curproxy->errmsg.msg503 == NULL) {
	    curproxy->errmsg.msg503 = (char *)HTTP_503;
	    curproxy->errmsg.len503 = strlen(HTTP_503);
	}
	if (curproxy->errmsg.msg504 == NULL) {
	    curproxy->errmsg.msg504 = (char *)HTTP_504;
	    curproxy->errmsg.len504 = strlen(HTTP_504);
	}
	curproxy = curproxy->next;
    }
    if (cfgerr > 0) {
	Alert("Errors found in configuration file, aborting.\n");
	return -1;
    }
    else
	return 0;
}

#ifdef ENABLE_SPLICE
void init_splice()
{
    int i;
    struct iovec v = { .iov_base = common_response,
		       .iov_len = sizeof(common_response) };
    int total, ret;

    if (global.flags & GFLAGS_NO_SPLICE)
	return;

    if (pipe(slave_pipe) < 0) {
	Alert("Failed to create pipes for splice\n");
	exit(1);
    }

    fcntl(slave_pipe[0], F_SETPIPE_SZ, pipesize * 5 / 4);

    /* initialize and fill pipes for the chunked mode */
    for (i=0; i<CHUNK_LEN; i++) {
	if (pipe(chunked_pipe[i]) < 0) {
	    Alert("Failed to create pipes for splice\n");
	    exit(1);
	}
	fcntl(chunked_pipe[i][0], F_SETPIPE_SZ, pipesize * 5 / 4);

	if (pipe(chunk_slave_pipe[i].pipe) < 0) {
	    Alert("Failed to create pipes for splice\n");
	    exit(1);
	}
	fcntl(chunk_slave_pipe[i].pipe[0], F_SETPIPE_SZ, pipesize * 5 / 4);

	chunk_slave_pipe[i].start_alignment = 0;
	chunk_slave_pipe[i].stop_alignment = 0;
	chunk_slave_pipe[i].usage = 0;

	v.iov_base = common_chunk_resp + i;
	v.iov_len = sizeof(common_chunk_resp) / CHUNK_LEN * CHUNK_LEN - CHUNK_LEN;
	total = ret = 0;
	do {
	    ret = vmsplice(chunked_pipe[i][1], &v, 1, SPLICE_F_NONBLOCK);
	    if (ret > 0)
		total += ret;
	} while (ret > 0 && total < pipesize);
    }
}
#endif

/*
 * This function initializes all the necessary variables. It only returns
 * if everything is OK. If something fails, it exits.
 */
void init(int argc, char **argv) {
    int i;
    int arg_mode = 0;	/* MODE_DEBUG, ... */
    char *old_argv = *argv;
    char *tmp;
    char *cfg_pidfile = NULL;

    if (1<<INTBITS != sizeof(int)*8) {
	fprintf(stderr,
		"Error: wrong architecture. Recompile so that sizeof(int)=%d\n",
		(int)(sizeof(int)*8));
	exit(1);
    }

#ifdef HTTPTERM_MEMMAX
    global.rlimit_memmax = HTTPTERM_MEMMAX;
#endif

    /* initialize the libc's localtime structures once for all so that we
     * won't be missing memory if we want to send alerts under OOM conditions.
     */
    tv_now(&now);
    localtime(&now.tv_sec);

    cfg_polling_mechanism = POLL_USE_SELECT;  /* select() is always available */
#if defined(ENABLE_POLL)
    cfg_polling_mechanism |= POLL_USE_POLL;
#endif
#if defined(ENABLE_EPOLL)
    cfg_polling_mechanism |= POLL_USE_EPOLL;
#endif

    pid = getpid();
    progname = *argv;
    while ((tmp = strchr(progname, '/')) != NULL)
	progname = tmp + 1;

    argc--; argv++;
    while (argc > 0) {
	char *flag;

	if (**argv == '-') {
	    flag = *argv+1;

	    /* 1 arg */
	    if (*flag == 'v') {
		display_version();
		exit(0);
	    }
#if defined(ENABLE_EPOLL)
	    else if (*flag == 'd' && flag[1] == 'e')
		cfg_polling_mechanism &= ~POLL_USE_EPOLL;
#endif
#if defined(ENABLE_POLL)
	    else if (*flag == 'd' && flag[1] == 'p')
		cfg_polling_mechanism &= ~POLL_USE_POLL;
#endif
#if defined(ENABLE_SPLICE)
	    else if (*flag == 'd' && flag[1] == 'S')
		global.flags |= GFLAGS_NO_SPLICE;
#endif
	    else if (*flag == 'V')
		arg_mode |= MODE_VERBOSE;
	    else if (*flag == 'd' && flag[1] == 'b')
		arg_mode |= MODE_FOREGROUND;
	    else if (*flag == 'd')
		arg_mode |= MODE_DEBUG;
	    else if (*flag == 'c')
		arg_mode |= MODE_CHECK;
	    else if (*flag == 'D')
		arg_mode |= MODE_DAEMON | MODE_QUIET;
	    else if (*flag == 'q')
		arg_mode |= MODE_QUIET;
	    else { /* >=2 args */
		argv++; argc--;
		if (argc == 0)
		    usage(old_argv);

		switch (*flag) {
		case 'n' : cfg_maxconn = atol(*argv); break;
		case 'm' : global.rlimit_memmax = atol(*argv); break;
		case 'N' : cfg_maxpconn = atol(*argv); break;
		case 'f' : cfg_cfgfile = *argv; break;
		case 'p' : cfg_pidfile = *argv; break;
		case 'L' : cmdline_listen = *argv; break;
#if defined(ENABLE_SPLICE)
		case 'P' : pipesize = atol(*argv) * 1024; break;
#endif
		default: usage(old_argv);
		}
	    }
	}
	else
	    usage(old_argv);
	argv++; argc--;
    }

    global.mode = MODE_STARTING | /* during startup, we want most of the alerts */
		  (arg_mode & (MODE_DAEMON | MODE_FOREGROUND | MODE_VERBOSE
			       | MODE_QUIET | MODE_CHECK | MODE_DEBUG));

    if (!cfg_cfgfile && !cmdline_listen)
	usage(old_argv);

    gethostname(hostname, MAX_HOSTNAME_LEN);

    global.maxsock = 10; /* reserve 10 fds ; will be incremented by socket eaters */
    if (readcfgfile(cfg_cfgfile) < 0) {
	Alert("Error reading configuration file : %s\n", cfg_cfgfile);
	exit(1);
    }

    if (global.mode & MODE_CHECK) {
	qfprintf(stdout, "Configuration file is valid : %s\n", cfg_cfgfile);
	exit(0);
    }

    if (!(global.flags & GFLAGS_SEND_ZERO)) {
	/* fill the common response with human-readable data : 50 bytes per line */
	for (i = 0; i < sizeof(common_response); i++) {
	    if (i % 50 == 49)
		common_response[i] = '\n';
	    else if (i % 10 == 0)
		common_response[i] = '.';
	    else
		common_response[i] = '0' + i % 10;
	}

	/* fill the common chunked response with chunk data */
	for (i = 0; i < sizeof(common_chunk_resp); i++)
	    common_chunk_resp[i] = chunk_pattern[i % CHUNK_LEN];
    }

    random_resp = malloc(random_resp_len);
    for (i = 0; i < random_resp_len; i++)
	random_resp[i] = rand() >> 16;

    if (cfg_maxconn > 0)
	global.maxconn = cfg_maxconn;

    if (cfg_pidfile) {
	if (global.pidfile)
	    free(global.pidfile);
	global.pidfile = strdup(cfg_pidfile);
    }

    if (global.maxconn == 0)
	global.maxconn = DEFAULT_MAXCONN;

    global.maxsock += global.maxconn; /* each connection needs one sockets */

    if (arg_mode & (MODE_DEBUG | MODE_FOREGROUND)) {
	/* command line debug mode inhibits configuration mode */
	global.mode &= ~(MODE_DAEMON | MODE_QUIET);
    }
    global.mode |= (arg_mode & (MODE_DAEMON | MODE_FOREGROUND | MODE_QUIET |
				MODE_VERBOSE | MODE_DEBUG));

    if ((global.mode & MODE_DEBUG) && (global.mode & (MODE_DAEMON | MODE_QUIET))) {
	Warning("<debug> mode incompatible with <quiet> and <daemon>. Keeping <debug> only.\n");
	global.mode &= ~(MODE_DAEMON | MODE_QUIET);
    }

    if ((global.nbproc > 1) && !(global.mode & MODE_DAEMON)) {
	if (!(global.mode & (MODE_FOREGROUND | MODE_DEBUG)))
	    Warning("<nbproc> is only meaningful in daemon mode. Setting limit to 1 process.\n");
	global.nbproc = 1;
    }

    if (global.nbproc < 1)
	global.nbproc = 1;

    StaticReadEvent = (fd_set *)calloc(1,
		sizeof(fd_set) *
		(global.maxsock + FD_SETSIZE - 1) / FD_SETSIZE);
    StaticWriteEvent = (fd_set *)calloc(1,
		sizeof(fd_set) *
		(global.maxsock + FD_SETSIZE - 1) / FD_SETSIZE);

    fdtab = (struct fdtab *)calloc(1,
		sizeof(struct fdtab) * (global.maxsock));
    for (i = 0; i < global.maxsock; i++) {
	fdtab[i].state = FD_STCLOSE;
    }

#ifdef ENABLE_SPLICE
    if (!(global.flags & GFLAGS_NO_SPLICE)) {
	struct iovec v = { .iov_base = common_response,
			   .iov_len = sizeof(common_response) };
	int total, ret;

	if (pipe(master_pipe) < 0) {
	    Alert("Failed to create master pipe for splice\n");
	    exit(1);
	}

	fcntl(master_pipe[0], F_SETPIPE_SZ, pipesize * 5 / 4);

	total = ret = 0;
	do {
	    ret = vmsplice(master_pipe[1], &v, 1, SPLICE_F_NONBLOCK);
	    if (ret > 0)
		total += ret;
	} while (ret > 0 && total < pipesize);

	if (total < pipesize) {
	    if (total < 60*1024) {
		/* Older kernels were limited to around 60-61 kB */
		Alert("Failed to vmsplice response buffer after %d bytes, retry with '-dS'\n", total);
		exit(1);
	    } else {
		Warning("Splicing is limited to %d bytes (too old kernel), retry with '-dS'\n", total);
		pipesize = total;
	    }
	}
    }
#endif
}

/*
 * this function starts all the proxies. Its return value is composed from
 * ERR_NONE, ERR_RETRYABLE and ERR_FATAL. Retryable errors will only be printed
 * if <verbose> is not zero.
 */
int start_proxies(int verbose) {
    struct proxy *curproxy;
    struct listener *listener;
    int err = ERR_NONE;
    int fd, pxerr;

    for (curproxy = proxy; curproxy != NULL; curproxy = curproxy->next) {
        if (curproxy->state != PR_STNEW)
	    continue; /* already initialized */

	pxerr = 0;
	for (listener = curproxy->listen; listener != NULL; listener = listener->next) {
	    if (listener->fd != -1)
		continue; /* already initialized */

	    if ((fd = socket(listener->addr.ss_family, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		if (verbose)
		    Alert("cannot create listening socket for proxy %s. Aborting.\n",
			  curproxy->id);
		err |= ERR_RETRYABLE;
		pxerr |= 1;
	        continue;
	    }
	
	    if (fd >= global.maxsock) {
		Alert("socket(): not enough free sockets for proxy %s. Raise -n argument. Aborting.\n",
		      curproxy->id);
		close(fd);
		err |= ERR_FATAL;
		pxerr |= 1;
		break;
	    }

	    if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
		Alert("cannot make socket non-blocking for proxy %s. Aborting.\n",
		      curproxy->id);
		close(fd);
		err |= ERR_FATAL;
		pxerr |= 1;
		break;
	    }

	    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &one, sizeof(one)) == -1) {
		Alert("cannot do so_reuseaddr for proxy %s. Continuing.\n",
		      curproxy->id);
	    }

	    /* this one may silently fail */
#ifdef SO_REUSEPORT
	    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (char *) &one, sizeof(one));
#endif

	    if (bind(fd,
		     (struct sockaddr *)&listener->addr,
		     listener->addr.ss_family == AF_INET6 ?
		     sizeof(struct sockaddr_in6) :
		     sizeof(struct sockaddr_in)) == -1) {
		if (verbose)
		    Alert("cannot bind socket for proxy %s. Aborting.\n",
			  curproxy->id);
		close(fd);
		err |= ERR_RETRYABLE;
		pxerr |= 1;
		continue;
	    }
	
	    if (listen(fd, curproxy->maxconn) == -1) {
		if (verbose)
		    Alert("cannot listen to socket for proxy %s. Aborting.\n",
			  curproxy->id);
		close(fd);
		err |= ERR_RETRYABLE;
		pxerr |= 1;
		continue;
	    }
	
	    /* the socket is ready */
	    listener->fd = fd;

#ifdef TCP_QUICKACK
	    /* we don't want quick ACKs there */
	    setsockopt(fd, SOL_TCP, TCP_QUICKACK, (char *) &zero, sizeof(zero));
#endif
#ifdef TCP_CORK
	    /* don't send partial frames, and merge FIN with last ACK */
	    if (!MSG_MORE)
		setsockopt(fd, SOL_TCP, TCP_CORK, (char *) &one, sizeof(one));
#endif

	    /* the function for the accept() event */
	    fdtab[fd].read  = &event_accept;
	    fdtab[fd].write = NULL; /* never called */
	    fdtab[fd].owner = (struct task *)curproxy; /* reference the proxy instead of a task */
	    fdtab[fd].state = FD_STLISTEN;
	    FD_SET(fd, StaticReadEvent);
	    fd_insert(fd);
	    listeners++;
	}

	if (!pxerr) {
	    curproxy->state = PR_STRUN;
	}
    }

    return err;
}

void pool_destroy(void **pool)
{
    void *temp, *next;
    next = pool;
    while (next) {
	temp = next;
	next = *(void **)temp;
	free(temp);
    }
}/* end pool_destroy() */

void deinit(void) {
    struct proxy *p = proxy;
    struct server *s,*s_next;
    struct listener *l,*l_next;
  
    while (p) {
	if (p->id)
	    free(p->id);

	/* only strup if the user have set in config.
	   When should we free it?!
	   if (p->errmsg.msg400) free(p->errmsg.msg400);
	   if (p->errmsg.msg403) free(p->errmsg.msg403);
	   if (p->errmsg.msg408) free(p->errmsg.msg408);
	   if (p->errmsg.msg500) free(p->errmsg.msg500);
	   if (p->errmsg.msg502) free(p->errmsg.msg502);
	   if (p->errmsg.msg503) free(p->errmsg.msg503);
	   if (p->errmsg.msg504) free(p->errmsg.msg504);
	*/

	s = p->srv;
	while (s) {
	    s_next = s->next;
	    if (s->id)
		free(s->id);
	    
	    free(s);
	    s = s_next;
	}/* end while(s) */
	
	l = p->listen;
	while (l) {
	    l_next = l->next;
	    free(l);
	    l = l_next;
	}/* end while(l) */
	
	p = p->next;
    }/* end while(p) */
    
    if (global.chroot)    free(global.chroot);
    if (global.pidfile)   free(global.pidfile);
    
    if (StaticReadEvent)  free(StaticReadEvent);
    if (StaticWriteEvent) free(StaticWriteEvent);
    if (fdtab)            free(fdtab);
    
    pool_destroy(pool_session);
    pool_destroy(pool_buffer);
    pool_destroy(pool_fdtab);
    pool_destroy(pool_task);
    
} /* end deinit() */

int main(int argc, char **argv) {
    int err;
    struct rlimit limit;
    FILE *pidfile = NULL;
    init(argc, argv);

    signal(SIGHUP, sig_dump_state);

    /* on very high loads, a sigpipe sometimes happen just between the
     * getsockopt() which tells "it's OK to write", and the following write :-(
     */
    signal(SIGPIPE, SIG_IGN);

    /* We will loop at most 100 times with 10 ms delay each time.
     * That's at most 1 second. We only send a signal to old pids
     * if we cannot grab at least one port.
     */
    err = start_proxies(1);

    /* Note: start_proxies() sends an alert when it fails. */
    if (err != ERR_NONE) {
	exit(1);
    }

    if (listeners == 0) {
	Alert("[%s.main()] No enabled listener found (check the <listen> keywords) ! Exiting.\n", argv[0]);
	/* Note: we don't have to send anything to the old pids because we
	 * never stopped them. */
	exit(1);
    }

    if (global.mode & MODE_DAEMON) {
	global.mode &= ~MODE_VERBOSE;
	global.mode |= MODE_QUIET;
    }

    /* MODE_QUIET can inhibit alerts and warnings below this line */

    global.mode &= ~MODE_STARTING;
    if ((global.mode & MODE_QUIET) && !(global.mode & MODE_VERBOSE)) {
	/* detach from the tty */
	fclose(stdin); fclose(stdout); fclose(stderr);
	close(0); close(1); close(2);
    }

    /* open pid files before the chroot */
    if (global.mode & MODE_DAEMON && global.pidfile != NULL) {
	int pidfd;
	unlink(global.pidfile);
	pidfd = open(global.pidfile, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (pidfd < 0) {
	    Alert("[%s.main()] Cannot create pidfile %s\n", argv[0], global.pidfile);
	    exit(1);
	}
	pidfile = fdopen(pidfd, "w");
    }

    /* chroot if needed */
    if (global.chroot != NULL) {
	if (chroot(global.chroot) == -1) {
	    Alert("[%s.main()] Cannot chroot(%s).\n", argv[0], global.chroot);
	}
	chdir("/");
    }

    /* ulimits */
    if (!global.rlimit_nofile)
	global.rlimit_nofile = global.maxsock;

    if (global.rlimit_nofile) {
	limit.rlim_cur = limit.rlim_max = global.rlimit_nofile;
	if (setrlimit(RLIMIT_NOFILE, &limit) == -1) {
	    Warning("[%s.main()] Cannot raise FD limit to %d.\n", argv[0], global.rlimit_nofile);
	}
    }

    if (global.rlimit_memmax) {
	limit.rlim_cur = limit.rlim_max =
		global.rlimit_memmax * 1048576 / global.nbproc;
#ifdef RLIMIT_AS
	if (setrlimit(RLIMIT_AS, &limit) == -1) {
	    Warning("[%s.main()] Cannot fix MEM limit to %d megs.\n",
		    argv[0], global.rlimit_memmax);
	}
#else
	if (setrlimit(RLIMIT_DATA, &limit) == -1) {
	    Warning("[%s.main()] Cannot fix MEM limit to %d megs.\n",
		    argv[0], global.rlimit_memmax);
	}
#endif
    }

    /* Note that any error at this stage will be fatal because we will not
     * be able to restart the old pids.
     */

    /* setgid / setuid */
    if (global.gid && setgid(global.gid) == -1) {
	Alert("[%s.main()] Cannot set gid %d.\n", argv[0], global.gid);
	exit(1);
    }

    if (global.uid && setuid(global.uid) == -1) {
	Alert("[%s.main()] Cannot set uid %d.\n", argv[0], global.uid);
	exit(1);
    }

    /* check ulimits */
    limit.rlim_cur = limit.rlim_max = 0;
    getrlimit(RLIMIT_NOFILE, &limit);
    if (limit.rlim_cur < global.maxsock) {
	Warning("[%s.main()] FD limit (%d) too low for maxconn=%d/maxsock=%d. Please raise 'ulimit-n' to %d or more to avoid any trouble.\n",
		argv[0], limit.rlim_cur, global.maxconn, global.maxsock, global.maxsock);
    }

    if (global.mode & MODE_DAEMON) {
	int ret = 0;
	int proc;

	/* the father launches the required number of processes */
	for (proc = 0; proc < global.nbproc; proc++) {
	    ret = fork();
	    if (ret < 0) {
		Alert("[%s.main()] Cannot fork.\n", argv[0]);
		exit(1); /* there has been an error */
	    }
	    else if (ret == 0) /* child breaks here */
		break;
	    if (pidfile != NULL) {
		fprintf(pidfile, "%d\n", ret);
		fflush(pidfile);
	    }
	}
	/* close the pidfile both in children and father */
	if (pidfile != NULL)
	    fclose(pidfile);
	free(global.pidfile);

	if (proc == global.nbproc)
	    exit(0); /* parent must leave */

	/* if we're NOT in QUIET mode, we should now close the 3 first FDs to ensure
	 * that we can detach from the TTY. We MUST NOT do it in other cases since
	 * it would have already be done, and 0-2 would have been affected to listening
	 * sockets
	 */
    	if (!(global.mode & MODE_QUIET)) {
	    /* detach from the tty */
	    fclose(stdin); fclose(stdout); fclose(stderr);
	    close(0); close(1); close(2); /* close all fd's */
    	    global.mode |= MODE_QUIET; /* ensure that we won't say anything from now */
	}
	pid = getpid(); /* update child's pid */
	setsid();
    }

#ifdef ENABLE_SPLICE
    init_splice();
#endif

#if defined(ENABLE_EPOLL)
    if (cfg_polling_mechanism & POLL_USE_EPOLL) {
	if (epoll_loop(POLL_LOOP_ACTION_INIT)) {
	    epoll_loop(POLL_LOOP_ACTION_RUN);
	    epoll_loop(POLL_LOOP_ACTION_CLEAN);
	    cfg_polling_mechanism &= POLL_USE_EPOLL;
	}
	else {
	    Warning("epoll() is not available. Using poll()/select() instead.\n");
	    cfg_polling_mechanism &= ~POLL_USE_EPOLL;
	}
    }
#endif

#if defined(ENABLE_POLL)
    if (cfg_polling_mechanism & POLL_USE_POLL) {
	if (poll_loop(POLL_LOOP_ACTION_INIT)) {
	    poll_loop(POLL_LOOP_ACTION_RUN);
	    poll_loop(POLL_LOOP_ACTION_CLEAN);
	    cfg_polling_mechanism &= POLL_USE_POLL;
	}
	else {
	    Warning("poll() is not available. Using select() instead.\n");
	    cfg_polling_mechanism &= ~POLL_USE_POLL;
	}
    }
#endif
    if (cfg_polling_mechanism & POLL_USE_SELECT) {
	if (select_loop(POLL_LOOP_ACTION_INIT)) {
	    select_loop(POLL_LOOP_ACTION_RUN);
	    select_loop(POLL_LOOP_ACTION_CLEAN);
	    cfg_polling_mechanism &= POLL_USE_SELECT;
	}
    }


    /* Do some cleanup */ 
    deinit();
    
    exit(0);
}


/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 * End:
 */
