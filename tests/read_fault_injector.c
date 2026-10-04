/* LD_PRELOAD read-fault injector for the sealmark regression tests.
 *
 * Simulates a regular file that opens fine and yields its first bytes
 * normally, then fails mid-stream: once SEALMARK_FAULT_AFTER bytes of the
 * file named by SEALMARK_FAULT_PATH have been delivered to the process,
 * the next read of that file fails with EIO.  Every other file and every
 * earlier byte behaves exactly as without the injector, so the exercised
 * program cannot tell the difference from a genuine I/O error.
 *
 * Configuration (environment):
 *   SEALMARK_FAULT_PATH    path of the file whose reads should start
 *                          failing; compared against the canonical path,
 *                          so it identifies the file, not the fd number
 *   SEALMARK_FAULT_AFTER   number of bytes to serve before the first
 *                          failure (must be > 0 and smaller than the file)
 *   SEALMARK_FAULT_REPORT  optional path of a file the injector writes
 *                          the number of successfully served bytes to at
 *                          the moment the fault is injected, so tests can
 *                          verify the failure really happened mid-stream
 *
 * Both the raw read(2) path and the stdio fread(3) path are interposed
 * (libstdc++ filebuf implementations use one or the other depending on
 * version and build configuration).  For the stdio path ferror(3) is
 * interposed as well, because a failed fread is only distinguishable
 * from EOF through the stream's error indicator.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

typedef ssize_t (*read_fn)(int, void *, size_t);
typedef size_t (*fread_fn)(void *, size_t, size_t, FILE *);
typedef size_t (*fread_chk_fn)(void *, size_t, size_t, size_t, FILE *);
typedef int (*ferror_fn)(FILE *);

static read_fn real_read;
static fread_fn real_fread;
static fread_fn real_fread_unlocked;
static fread_chk_fn real_fread_chk;
static ferror_fn real_ferror;
static ferror_fn real_ferror_unlocked;

static char target_path[PATH_MAX]; /* canonical path of the rigged file */
static int have_target;
static long long fault_after = -1; /* bytes to serve before failing; <0: off */
static char report_path[PATH_MAX];
static int have_report;

static int target_fd = -1;      /* caches the fd once identified */
static long long served;        /* bytes delivered for the target so far */
static int fault_injected;      /* a read has already been failed */
static int report_written;

__attribute__((constructor)) static void injector_init(void) {
    real_read = (read_fn)dlsym(RTLD_NEXT, "read");
    real_fread = (fread_fn)dlsym(RTLD_NEXT, "fread");
    real_fread_unlocked = (fread_fn)dlsym(RTLD_NEXT, "fread_unlocked");
    real_fread_chk = (fread_chk_fn)dlsym(RTLD_NEXT, "__fread_chk");
    real_ferror = (ferror_fn)dlsym(RTLD_NEXT, "ferror");
    real_ferror_unlocked = (ferror_fn)dlsym(RTLD_NEXT, "ferror_unlocked");

    const char *target = getenv("SEALMARK_FAULT_PATH");
    const char *after = getenv("SEALMARK_FAULT_AFTER");
    if (target && after) {
        char resolved[PATH_MAX];
        const char *canonical = realpath(target, resolved);
        snprintf(target_path, sizeof(target_path), "%s",
                 canonical ? canonical : target);
        fault_after = atoll(after);
        have_target = 1;
    }
    const char *report = getenv("SEALMARK_FAULT_REPORT");
    if (report) {
        snprintf(report_path, sizeof(report_path), "%s", report);
        have_report = 1;
    }
}

/* Records how many bytes were served before the fault, using raw syscalls
 * so the report path cannot recurse into the interposed functions. */
static void write_report(void) {
    if (report_written || !have_report)
        return;
    report_written = 1;
    char buf[64];
    int len = snprintf(buf, sizeof(buf), "%lld\n", served);
    if (len <= 0)
        return;
    long fd = syscall(SYS_openat, AT_FDCWD, report_path,
                      O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return;
    syscall(SYS_write, (int)fd, buf, (size_t)len);
    syscall(SYS_close, (int)fd);
}

static int inject_fault(void) {
    fault_injected = 1;
    write_report();
    errno = EIO;
    return 1;
}

static int is_target_fd(int fd) {
    if (!have_target || fd < 0)
        return 0;
    if (fd == target_fd)
        return 1;
    char linkpath[64];
    snprintf(linkpath, sizeof(linkpath), "/proc/self/fd/%d", fd);
    char buf[PATH_MAX];
    ssize_t n = readlink(linkpath, buf, sizeof(buf) - 1);
    if (n <= 0 || (size_t)n >= sizeof(buf))
        return 0;
    buf[n] = '\0';
    if (strcmp(buf, target_path) != 0)
        return 0;
    target_fd = fd;
    return 1;
}

/* The fault fires only once the budget has been served in full; reads up
 * to that point pass through untouched so partial content really reaches
 * the program before the failure. */
static int should_fail(void) {
    return have_target && fault_after >= 0 && served >= fault_after;
}

ssize_t read(int fd, void *buf, size_t count) {
    if (is_target_fd(fd)) {
        if (should_fail()) {
            inject_fault();
            return -1;
        }
        ssize_t n = real_read(fd, buf, count);
        if (n > 0)
            served += n;
        return n;
    }
    return real_read(fd, buf, count);
}

static size_t fread_common(void *ptr, size_t size, size_t nmemb, FILE *stream,
                           fread_fn real) {
    if (should_fail()) {
        inject_fault();
        return 0; /* paired with the interposed ferror below */
    }
    size_t n = real(ptr, size, nmemb, stream);
    served += (long long)n * (long long)size;
    return n;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    if (have_target && is_target_fd(fileno(stream)))
        return fread_common(ptr, size, nmemb, stream, real_fread);
    return real_fread(ptr, size, nmemb, stream);
}

size_t fread_unlocked(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    if (have_target && is_target_fd(fileno(stream)))
        return fread_common(ptr, size, nmemb, stream, real_fread_unlocked);
    return real_fread_unlocked(ptr, size, nmemb, stream);
}

size_t __fread_chk(void *ptr, size_t ptrlen, size_t size, size_t nmemb,
                   FILE *stream) {
    if (have_target && is_target_fd(fileno(stream))) {
        if (should_fail()) {
            inject_fault();
            return 0;
        }
        size_t n = real_fread_chk(ptr, ptrlen, size, nmemb, stream);
        served += (long long)n * (long long)size;
        return n;
    }
    return real_fread_chk(ptr, ptrlen, size, nmemb, stream);
}

/* A failed fread is only distinguishable from EOF via the error
 * indicator, so report one for the rigged stream once the fault fired. */
static int ferror_common(FILE *stream, ferror_fn real) {
    if (fault_injected && is_target_fd(fileno(stream)))
        return 1;
    return real(stream);
}

int ferror(FILE *stream) {
    if (fault_injected)
        return ferror_common(stream, real_ferror);
    return real_ferror(stream);
}

int ferror_unlocked(FILE *stream) {
    if (fault_injected)
        return ferror_common(stream, real_ferror_unlocked);
    return real_ferror_unlocked(stream);
}
