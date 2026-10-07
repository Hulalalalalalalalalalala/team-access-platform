/*
 * Per-child resource-usage reporter for the sealmark regression suite.
 *
 * The rule under test for key-id is a memory bound: the memory the process
 * itself uses to handle its input must not grow with the amount of legal
 * ASCII whitespace surrounding the PUBLIC KEY block -- not before it, not
 * after it (the parser must keep classifying bytes to EOF), and not for a
 * file that is whitespace and nothing else. A correct implementation reads
 * in fixed-size passes and discards whitespace as it classifies it, so its
 * peak resident set size does not track those padding lengths; a degenerate
 * implementation that accumulates the whole file (or the whitespace run, or
 * the bytes after the completed block) in memory shows an RSS that grows
 * proportionally with it.
 *
 * Why this helper exists
 * ----------------------
 *
 * Measuring the child's peak RSS from Python is unreliable on Linux:
 * RUSAGE_CHILDREN is an aggregate that includes the interpreter itself and
 * every previously reaped child, and RUSAGE_SELF reports the Python driver,
 * not sealmark. The clean signal is obtained exactly as /usr/bin/time -v
 * obtains it: fork() a tiny parent, execv() the program under test in the
 * child, and read ru_maxrss out of the rusage filled by wait4() -- the peak
 * resident set size of the sealmark child alone, never affected by the
 * Python test driver or by the pipes used to capture its output.
 *
 * Usage:
 *
 *   rusage_wrap <report-file> <program> [args...]
 *
 * The wrapper forks, execs <program> with the given args (no shell), and
 * waits for it. While waiting it collects the child's rusage via wait4();
 * after reaping it writes two lines to <report-file>:
 *
 *   maxrss_kb=<peak resident set size of the child in KiB>
 *   exit_status=<child exit code>            (when the child exited normally)
 *   exit_signal=<signal killing the child>   (when the child died by signal)
 *
 * It then exits with the same exit code as the child (or 128+signal when
 * the child was killed by a signal), preserving the child's stdout/stderr
 * streams untouched -- they belong to the wrapper's own stdout/stderr,
 * which ctest/Python capture directly.
 *
 * This is a measurement helper, not an injector: it neither injects faults
 * nor mutates anything; it only reports what wait4 saw. Linux only.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "rusage_wrap: usage: rusage_wrap <report-file> "
                        "<program> [args...]\n");
        return 64;
    }
    const char *report_path = argv[1];
    char *const *child_argv = &argv[2];

    pid_t pid = fork();
    if (pid < 0) {
        perror("rusage_wrap: fork");
        return 64;
    }
    if (pid == 0) {
        execv(child_argv[0], child_argv);
        fprintf(stderr, "rusage_wrap: cannot exec '%s': %s\n", child_argv[0],
                strerror(errno));
        _exit(127);
    }

    int status = 0;
    struct rusage ru;
    pid_t waited;
    do {
        waited = wait4(pid, &status, 0, &ru);
    } while (waited < 0 && errno == EINTR);
    if (waited < 0) {
        perror("rusage_wrap: wait4");
        return 64;
    }

    FILE *f = fopen(report_path, "w");
    if (!f) {
        perror("rusage_wrap: open report");
        return 64;
    }
    fprintf(f, "maxrss_kb=%ld\n", (long)ru.ru_maxrss);
    if (WIFEXITED(status)) {
        fprintf(f, "exit_status=%d\n", WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        fprintf(f, "exit_signal=%d\n", WTERMSIG(status));
    }
    if (fclose(f) != 0) {
        perror("rusage_wrap: write report");
        return 64;
    }

    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }
    return 64;
}
