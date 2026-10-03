/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * straddle-probe: one instruction that needs six device pages mapped at
 * once, for a guest on a femu-cxl-ssd with der=uffd. A movsq whose two code
 * bytes straddle a page boundary reads 8 bytes that straddle the next one
 * and writes 8 bytes that straddle a third. Each round uses six fresh pages
 * of the devdax mapping, mapped executable. With fewer ways per set than
 * that, filling the sixth page evicts one of the first, and the instruction
 * finishes only if the device keeps them for it. Prints one JSON object.
 *
 *   gcc -O2 -o straddle-probe straddle-probe.c
 *   ./straddle-probe [rounds] [first page] [dax device] [seconds]
 */
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t done_rounds;
static int rounds;

static uint64_t now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

static void timeout(int sig)
{
    (void)sig;
    dprintf(1, "{\"rounds\": %d, \"done\": %d, \"killed\": true}\n", rounds,
            (int)done_rounds);
    _exit(0);
}

int main(int argc, char **argv)
{
    long first = argc > 2 ? atol(argv[2]) : 4096;
    const char *dev = argc > 3 ? argv[3] : "/dev/dax0.0";
    int limit = argc > 4 ? atoi(argv[4]) : 60;
    struct sigaction sa = { .sa_handler = timeout };
    uint64_t max_ns = 0, sum_ns = 0;
    uint8_t *cxl;
    int bad = 0;
    int fd;

    rounds = argc > 1 ? atoi(argv[1]) : 100;
    fd = open(dev, O_RDWR);
    if (fd < 0) {
        perror(dev);
        return 1;
    }
    cxl = mmap(NULL, 1ul << 30, PROT_READ | PROT_WRITE | PROT_EXEC,
               MAP_SHARED, fd, 0);
    if (cxl == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    sigaction(SIGALRM, &sa, NULL);
    alarm(limit);
    for (int r = 0; r < rounds; r++) {
        uint8_t *code = cxl + (first + 6 * r) * 4096;  /* pages p and p+1 */
        uint8_t *src = code + 2 * 4096 + 4092;         /* p+2 and p+3 */
        uint8_t *dst = code + 4 * 4096 + 4092;         /* p+4 and p+5 */
        uint64_t want = 0x0123456789abcdefull ^ r;
        uint64_t got;
        uint64_t t0;
        uint64_t ns;

        code[4095] = 0x48;          /* movsq, 48 a5, across p and p+1 */
        code[4096] = 0xa5;
        code[4097] = 0xc3;          /* ret */
        memcpy(src, &want, 8);
        memset(dst, 0, 8);
        /* Touch 64 other pages, so a small cache holds none of the six. */
        for (int k = 0; k < 64; k++) {
            uint64_t page = first + 6 * rounds + 64 + 64 * r + k;

            /* volatile: the load is the point, not its value. */
            (void)*(volatile uint8_t *)(cxl + page * 4096);
        }
        t0 = now_ns();
        __asm__ volatile("call *%2"
                         : "+S"(src), "+D"(dst)
                         : "r"(code + 4095)
                         : "memory", "cc", "rax", "rcx", "rdx", "r8", "r9",
                           "r10", "r11");
        ns = now_ns() - t0;
        memcpy(&got, cxl + (first + 6 * r + 4) * 4096 + 4092, 8);
        bad += got != want;
        sum_ns += ns;
        max_ns = ns > max_ns ? ns : max_ns;
        done_rounds = r + 1;
    }
    alarm(0);
    printf("{\"rounds\": %d, \"done\": %d, \"killed\": false, "
           "\"mismatches\": %d, \"mean_us\": %.1f, \"max_us\": %.1f}\n",
           rounds, (int)done_rounds, bad, sum_ns / 1e3 / rounds,
           max_ns / 1e3);
    return 0;
}
