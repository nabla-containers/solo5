#include "solo5.h"
int write(int fd, void* data, int nbytes)
{
    int ret;
    // 1 ==  SYS_write
    asm volatile(
        "syscall" : "=a" (ret) : "0"(1), "D"(fd), "S"(data), "d"(nbytes));
    return ret;
}


int get_pid()
{
    int ret;
    // 39 ==  SYS_getpid
    asm volatile("syscall" : "=a" (ret) : "0"(39) );
    return ret;
}

void digit_to_char(int num)
{
    char chr = 48 + num;
    write(1, &chr, 1);
}

void digits_to_char(int num)
{
    if(num < 10)
    {
        digit_to_char(num);
    }
    else
    {
        digits_to_char(num/10);
        digit_to_char(num%10);
    }
}

int solo5_app_main(const struct solo5_start_info *si __attribute__((unused)))
{
    write(1, "hello world\n", 13);
    int pid = get_pid();
    digits_to_char(pid);
    return SOLO5_EXIT_SUCCESS;
}
