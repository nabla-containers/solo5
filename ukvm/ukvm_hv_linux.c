/* 
 * Copyright (c) 2015-2017 Contributors as noted in the AUTHORS file
 *
 * This file is part of ukvm, a unikernel monitor.
 *
 * Permission to use, copy, modify, and/or distribute this software
 * for any purpose with or without fee is hereby granted, provided
 * that the above copyright notice and this permission notice appear
 * in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
 * OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * ukvm_hv_linux.c: Architecture-independent part of Linux backend
 * implementation.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <linux/kvm.h>
#include <stdio.h>

#include <seccomp.h> /* from libseccomp-dev */

#include "ukvm.h"
#include "ukvm_hv_linux.h"

void install_syscall_filter(void)
{
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);

    /* 
     * For core module.
     *
     * XXX move into core module so we can get the actual pollfd
     * structure for poll.  Right now we can only say that the number
     * of fds is 0.
     *
     */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
                     SCMP_A0(SCMP_CMP_EQ, 1));
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ppoll), 1,
                     SCMP_A1(SCMP_CMP_EQ, 0));

    /* 
     * For blk module.
     *
     * XXX move to block module so we can get the fd for pread/write.
     * Hardcoding 4 only worked some of the time.
     */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pwrite64), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pread64), 0);
    /* seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pwrite64), 1, */
    /*                  SCMP_A0(SCMP_CMP_EQ, 4)); */
    /* seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pread64), 1, */
    /*                  SCMP_A0(SCMP_CMP_EQ, 4)); */

    /* 
     * For net module. 
     *
     *  XXX move to net module so we can get the fd for read/write,
     *  but hardcoding 3 seems to be working for now.
     *
     *  I'm not sure how to get the right fd there for poll... we need
     *  to point to the actual pollfd struct which will be in core,
     *  not net.  For now, just saying that polling with nfds=1 is OK.
     */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ppoll), 0);

    
    seccomp_load(ctx);
}


struct ukvm_hv *ukvm_hv_init(size_t mem_size)
{
    struct ukvm_hv *hv = malloc(sizeof (struct ukvm_hv));
    if (hv == NULL)
        err(1, "malloc");
    memset(hv, 0, sizeof (struct ukvm_hv));
    struct ukvm_hvb *hvb = malloc(sizeof (struct ukvm_hvb));
    if (hvb == NULL)
        err(1, "malloc");
    memset(hvb, 0, sizeof (struct ukvm_hvb));

    hvb->realmem = mmap((void *)LINUX_MAP_ADDRESS,
                        mem_size - LINUX_MAP_ADDRESS, PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (hvb->realmem == MAP_FAILED)
        err(1, "Error allocating guest memory");

    assert((uint64_t)hvb->realmem == LINUX_MAP_ADDRESS);

    /*
     * This is a bit of a nasty hack.
     *
     * hv->mem is at 0 so the unmodified unikernel ELF can be loaded
     * assuming its addressing starts at 0 (as it does when running as
     * a VM).  The unikernel doesn't use the really low memory (below
     * LINUX_MAP_ADDRESS), so it ends up being OK that we don't
     * actually allocate that.
     */
    hv->mem = 0; 
    hv->mem_size = mem_size;

    hv->b = hvb;
    return hv;
}


static void ukvm_hv_handle_exit(int nr, void *arg);

/* Yikes. Using rdtsc for timing is a bit suspect. */
uint64_t get_cpuinfo_freq(void)
{
    FILE *cpuinfo = fopen("/proc/cpuinfo", "rb");
    int ghz=0, mhz=0;
    char buf[256];
    
    do {
        char *ptr;
        ptr = fgets(buf, 256, cpuinfo);
        if (!ptr)
            continue;
                
        ptr = strstr(buf, "GHz");
        if (!ptr)
            continue;

        sscanf(ptr - 4, "%d.%d", &ghz, &mhz);
        break;
    } while(!feof(cpuinfo));

    fclose(cpuinfo);
    return ((uint64_t)ghz * 1000000000 + (uint64_t)mhz * 10000000);
}


void ukvm_hv_vcpu_init(struct ukvm_hv *hv, ukvm_gpa_t gpa_ep,
                       ukvm_gpa_t gpa_kend, char **cmdline)
{
    struct ukvm_boot_info *bi =
        (struct ukvm_boot_info *)(hv->mem + LINUX_BOOT_INFO_BASE);
    bi->mem_size = hv->mem_size;
    bi->kernel_end = gpa_kend;
    bi->cmdline = LINUX_CMDLINE_BASE;
    bi->cpu.tsc_freq =   get_cpuinfo_freq();
    
    uint64_t *hypercall_ptr = (uint64_t *)(hv->mem + LINUX_HYPERCALL_ADDRESS);
    *hypercall_ptr = (uint64_t)ukvm_hv_handle_exit;
    
    hv->b->entry = gpa_ep;
    hv->b->arg = bi;
        
    *cmdline = (char *)(hv->mem + LINUX_CMDLINE_BASE);
}

/* 
 * We could use pthreads for real "loop" behavior, but can avoid
 * pthreads because the ukvm "hypercalls" are synchronous.  We do need
 * to pass the hv structure to ukvm_hv_handle_exit though.
 */
static struct ukvm_hv *loop_hv;

void ukvm_hv_vcpu_loop(struct ukvm_hv *hv)
{
    void (*_start)(void *) = (void (*)(void *))hv->b->entry;
    loop_hv = hv;

    install_syscall_filter();

    /* 
     * First call into unikernel, call start.  Note we are sharing our
     * stack with the unikernel. 
     */
    _start(hv->b->arg);
}

/* Called directly by the unikernel. */
static void ukvm_hv_handle_exit(int nr, void *arg)
{
    struct ukvm_hv *hv = loop_hv;

    /* Guest has halted the CPU, this is considered as a normal exit. */
    if (nr == UKVM_HYPERCALL_HALT)
        exit(0);

    int handled = 0;
    for (ukvm_vmexit_fn_t *fn = ukvm_core_vmexits; *fn && !handled; fn++)
        handled = ((*fn)(hv) == 0);
    if (handled)
        return;

    if (nr <= 0 || nr >= (UKVM_HYPERCALL_MAX))
        errx(1, "Invalid guest port access: port=0x%x", nr);
    
    ukvm_hypercall_fn_t fn = ukvm_core_hypercalls[nr];
    if (fn == NULL)
        errx(1, "Invalid guest hypercall: num=%d", nr);
    
    ukvm_gpa_t gpa = (ukvm_gpa_t)arg;
    fn(hv, gpa);
}
