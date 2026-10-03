/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * pt-stress: guest page tables on CXL memory. Run it bound to the node of a
 * femu-cxl-ssd region onlined as system RAM, so its anonymous memory and the
 * page tables that map it both live on the device:
 *
 *   gcc -O2 -pthread -o pt-stress pt-stress.c
 *   numactl --membind=<cxl node> ./pt-stress [MiB] [threads] [seconds]
 *
 * Each thread fills its slice of the region, 4 KiB pages without THP, then
 * reads random pages of it for the given time, checks each against what it
 * wrote, and writes it again. Every access may need the data page and up to
 * three page-table pages of the device mapped at once. Prints one JSON object
 * with the accesses made and the mismatches found.
 */
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <time.h>

typedef struct {
    uint64_t *base;
    uint64_t pages;
    unsigned seed;
    int seconds;
    uint64_t ops;
    uint64_t bad;
} Slice;

static uint64_t value(uint64_t *base, uint64_t page)
{
    return ((uintptr_t)base >> 12) + page * 0x9e3779b97f4a7c15ull;
}

static void *run(void *opaque)
{
    Slice *s = opaque;
    struct timespec t0, t;
    uint64_t page;

    for (page = 0; page < s->pages; page++) {
        s->base[page * 512] = value(s->base, page);
    }
    clock_gettime(CLOCK_MONOTONIC, &t0);
    do {
        for (int k = 0; k < 256; k++) {
            page = rand_r(&s->seed) % s->pages;
            s->bad += s->base[page * 512] != value(s->base, page);
            s->base[page * 512] = value(s->base, page);
            s->ops++;
        }
        clock_gettime(CLOCK_MONOTONIC, &t);
    } while (t.tv_sec - t0.tv_sec < s->seconds);
    return NULL;
}

int main(int argc, char **argv)
{
    uint64_t mib = argc > 1 ? atoll(argv[1]) : 256;
    int threads = argc > 2 ? atoi(argv[2]) : 4;
    int seconds = argc > 3 ? atoi(argv[3]) : 10;
    uint64_t pages = mib * 256 / threads;
    pthread_t tid[64];
    Slice slice[64];
    uint64_t ops = 0, bad = 0;

    if (threads < 1 || threads > 64 || !pages) {
        fprintf(stderr, "usage: pt-stress [MiB] [threads 1-64] [seconds]\n");
        return 2;
    }
    for (int i = 0; i < threads; i++) {
        uint64_t *p = mmap(NULL, pages * 4096, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        if (p == MAP_FAILED) {
            perror("mmap");
            return 1;
        }
        madvise(p, pages * 4096, MADV_NOHUGEPAGE);
        slice[i] = (Slice) {
            .base = p, .pages = pages, .seed = i + 1, .seconds = seconds,
        };
        pthread_create(&tid[i], NULL, run, &slice[i]);
    }
    for (int i = 0; i < threads; i++) {
        pthread_join(tid[i], NULL);
        ops += slice[i].ops;
        bad += slice[i].bad;
    }
    printf("{\"mib\": %llu, \"threads\": %d, \"seconds\": %d, \"ops\": %llu, "
           "\"mismatches\": %llu}\n", (unsigned long long)mib, threads,
           seconds, (unsigned long long)ops, (unsigned long long)bad);
    return 0;
}
