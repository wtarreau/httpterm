# HTTPTerm

HTTPTerm is a dummy HTTP/1.1 server that adjusts its behavior based on what it
receives in the request. This is essentially used for performance testing and
sometimes for compatibility testing of proxies or clients. The request can
specify a response delay, a number of bytes, a different status code, whether
or not to advertise the content-length (even advertise a fake one), to force
to close the connection, send 1-byte chunks to stress a client's parser, send
purely random data to stress a compressing proxy, send randomly sized pieces,
etc.

Although it does support a config file to emulate some applications, it's no
longer used this way as it supports listening on an IP:port from the command
line using the `-L` argument. It is an event-driven single-process, single-
threaded server, that makes use of `SO_REUSEPORT` to permit to start multiple
occurrences in parallel in increase performance on multi-CPU platforms.

It will accept as many concurrent connections as the number of allowed file
descriptors by default. The value may be forced using `-n` though.

A good practise is to start it on a number of CPUs that are tied to the network
card. When testing a local proxy, it makes sense to dedicate several CPUs to
the testing components (httpterm and a load generator) and other CPUs to the
component to be tested. There's no harm mixing httpterm and another component
on the same CPUs, since httpterm is lockless, it will not suffer from CPU
preemption.

## Examples
Start 16 processes on port 8000:
```
$ for i in {0..15}; do taskset -c 0-15 ./httpterm -D -L :8000; done
```

## Build it:
This is a GNU makefile, so let's use 'make' on Linux or 'gmake' on some other
platforms:

```
$ gmake
```
Some variables may be forced such as the target OS (`TARGET`), which defaults
to linux26s (i.e. any Linux >= 2.6.28 with splicing). Target-specific options
may be passed to TARGET_OPTS (e.g. optimizations). Other build options to be
appended later may be passed into `SMALL_OPTS`. The compiler can be forced in
CC, and the linker in LD if different. Eg:
```
$ make TARGET_OPTS="-O3 -march=x86_64" CC=gcc-12 SMALL_OPTS="-flto"
$ gmake TARGET=freebsd
```

## Testing
```
$ ./httpterm -D -L :8002
$ curl -i 0:8002/?h
HTTP/1.0 200
Cache-Control: no-cache
Connection: close
Content-type: text/plain

HTTPTerm-1.7.10 - 2024/10/10
All integer argument values are in the form [digits]*[kmgr] (r=random(0..1)).
The following arguments are supported to override the default objects :
 - /? or /?h         show this help.
 - /?s=<size>        return <size> bytes.
                     E.g. /?s=20k
 - /?r=<retcode>     present <retcode> as the HTTP return code.
                     E.g. /?r=404
 - /?c=<cache>       set the return as not cacheable if <1.
                     E.g. /?c=0
 - /?C=<close>       force the response to use close if >0.
                     E.g. /?C=1
 - /?K=<keep-alive>  force the response to use keep-alive if >0.
                     E.g. /?K=1
 - /?b=<bodylen>     <0: send content-length; 0: don't; >0: send this value.
                     E.g. /?b=0   /?b=100k
 - /?B=<maxbody>     read no more than this amount of body before responding.
                     E.g. /?B=10000
 - /?t=<time>        wait <time> milliseconds before responding.
                     E.g. /?t=500 , /?t=10k for 10s , /?t=5000r for 0..5s
 - /?w=<time>        use keep-alive time <time> milliseconds.
                     E.g. /?w=1000
 - /?P=<time>        pause <time> milliseconds after responding (may delay close).
 - /?e=<enable>      Enable sending of the Etag header if >0 (for use with caches).
 - /?k=<enable>      Enable transfer encoding chunked with 1 byte chunks if >0.
 - /?S=<enable>      Disable use of splice() to send data if <1.
 - /?R=<enable>      Enable sending random data if >0 (disables splicing).
 - /?p=<size>        Make pieces no larger than this if >0 (disables splicing).

Note that those arguments may be cumulated on one line separated by a set of
delimitors among [&?,;/] :
 -  GET /?s=20k&c=1&t=700&K=30r HTTP/1.0
 -  GET /?r=500?s=0?c=0?t=1000 HTTP/1.0

$ time curl -i 0:8002/?s=100/t=500
HTTP/1.1 200
Content-length: 100
X-req: size=92, time=0 ms
X-rsp: id=dummy, code=200, cache=1, size=100, time=500 ms (501 real)

.123456789.123456789.123456789.123456789.12345678
.123456789.123456789.123456789.123456789.12345678

real    0m0.505s
user    0m0.002s
sys     0m0.001s
```
