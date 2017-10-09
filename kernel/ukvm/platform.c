/* 
 * Copyright (c) 2015-2017 Contributors as noted in the AUTHORS file
 *
 * This file is part of Solo5, a unikernel base layer.
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

#include "kernel.h"

static const char *cmdline;
static uint64_t mem_size;
static uint64_t kernel_end;

void process_bootinfo(void *arg)
{
    struct ukvm_boot_info *bi = arg;

    cmdline = bi->cmdline;
    mem_size = bi->mem_size;

    /* TODO: check that in regular ukvm, _end matches kernel_end. */
    kernel_end = bi->kernel_end;

    /* This is just used on the hv_linux backend and it's harmless on the
     * regular ukvm */
    ukvm_linux_hypercall_ptr = bi->hypercall_ptr;
}

const char *platform_cmdline(void)
{
    return cmdline;
}

uint64_t platform_mem_size(void)
{
    return mem_size;
}

uint64_t platform_kernel_end(void)
{
    return kernel_end;
}

void platform_exit(void)
{
    /*
     * Halt will cause an exit (as in "shutdown") on ukvm.
     */
    //cpu_halt();
    ukvm_do_hypercall(UKVM_HYPERCALL_HALT, NULL);
    for(;;);
}
