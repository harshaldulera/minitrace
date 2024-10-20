#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>    /* For user_regs_struct */
#include <sys/syscall.h> /* For SYS_* definitions */
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>

#ifdef __x86_64__
#define REG_SYSCALL orig_rax
#define REG_RET rax
#define REG_ARG1 rdi
#define REG_ARG2 rsi
#define REG_ARG3 rdx
#define REG_ARG4 r10
#define REG_ARG5 r8
#define REG_ARG6 r9
#elif __i386__
#define REG_SYSCALL orig_eax
#define REG_RET eax
#define REG_ARG1 ebx
#define REG_ARG2 ecx
#define REG_ARG3 edx
#define REG_ARG4 esi
#define REG_ARG5 edi
#define REG_ARG6 ebp
#else
#error "Unsupported architecture"
#endif

/* Define a structure to hold syscall number and name */
typedef struct syscall_entry {
    int number;
    const char *name;
} syscall_entry;

/* Partial syscall table for demonstration purposes */
syscall_entry syscall_table[] = {
    {SYS_read, "read"},
    {SYS_write, "write"},
    {SYS_open, "open"},
    {SYS_close, "close"},
    {SYS_stat, "stat"},
    {SYS_fstat, "fstat"},
    {SYS_lstat, "lstat"},
    {SYS_mmap, "mmap"},
    {SYS_mprotect, "mprotect"},
    {SYS_brk, "brk"},
    {SYS_access, "access"},
    {SYS_execve, "execve"},
    {SYS_exit_group, "exit_group"},
    /* Add more syscalls as needed */
    {-1, NULL} /* Sentinel value */
};

/* Function to get syscall name from number */
const char *get_syscall_name(long syscall_number) {
    for (int i = 0; syscall_table[i].name != NULL; i++) {
        if (syscall_table[i].number == syscall_number) {
            return syscall_table[i].name;
        }
    }
    return "unknown";
}

void trace_pid(pid_t pid) {
    int status;
    int in_syscall = 0;
    struct user_regs_struct regs;

    waitpid(pid, &status, 0);

    while (1) {
        if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) {
            perror("ptrace");
            break;
        }

        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            printf("Process %d exited\n", pid);
            break;
        }

        if (in_syscall == 0) {
            /* Syscall entry */
            ptrace(PTRACE_GETREGS, pid, NULL, &regs);
            long syscall_number = regs.REG_SYSCALL;
            const char *syscall_name = get_syscall_name(syscall_number);

            printf("System call: %s(", syscall_name);

            /* Print arguments */
            printf("%#llx, %#llx, %#llx", (unsigned long long)regs.REG_ARG1,
                   (unsigned long long)regs.REG_ARG2, (unsigned long long)regs.REG_ARG3);
            /* For more arguments, add regs.REG_ARG4, etc. */

            printf(")");
            fflush(stdout);

            in_syscall = 1;
        } else {
            /* Syscall exit */
            ptrace(PTRACE_GETREGS, pid, NULL, &regs);
            long ret = regs.REG_RET;

            /* Check for error */
            if (ret < 0) {
                errno = -ret;
                printf(" = -1 (%s)\n", strerror(errno));
            } else {
                printf(" = %#llx\n", (unsigned long long)ret);
            }

            in_syscall = 0;
        }
    }
}

void run_and_trace(char *program, char **args) {
    pid_t child = fork();
    if (child == 0) {
        /* Child process */
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            perror("ptrace");
            exit(1);
        }
        execvp(program, args);
        perror("execvp");
        exit(1);
    } else if (child > 0) {
        /* Parent process */
        trace_pid(child);
    } else {
        perror("fork");
        exit(1);
    }
}

void attach_and_trace(pid_t pid) {
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("ptrace attach");
        exit(1);
    }
    waitpid(pid, NULL, 0); /* Wait for the process to stop */
    trace_pid(pid);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <pid> or <command> [args...]\n", argv[0]);
        exit(1);
    }

    if (isdigit(argv[1][0])) {
        /* Attach to an existing process */
        pid_t pid = atoi(argv[1]);
        attach_and_trace(pid);
    } else {
        /* Run and trace a new process */
        run_and_trace(argv[1], &argv[1]);
    }

    return 0;
}
