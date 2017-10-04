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

#include "ukvm.h"
#include "ukvm_hv_linux.h"

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

void ukvm_hv_vcpu_init(struct ukvm_hv *hv, ukvm_gpa_t gpa_ep,
                       ukvm_gpa_t gpa_kend, char **cmdline)
{
    struct ukvm_boot_info *bi =
        (struct ukvm_boot_info *)(hv->mem + LINUX_BOOT_INFO_BASE);
    bi->mem_size = hv->mem_size;
    bi->kernel_end = gpa_kend;
    bi->cmdline = LINUX_CMDLINE_BASE;

    /* XXX We should read this from /proc/cpuinfo */
    bi->cpu.tsc_freq = 899945000;

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
