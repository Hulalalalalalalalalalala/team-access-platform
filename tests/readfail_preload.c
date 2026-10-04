/*
 * Deterministic mid-read fault injector for the sealmark test-suite.
 *
 * Loaded through LD_PRELOAD (Linux), this interposes the libc read entry
 * points and turns reads of *one specific regular file* into failures after
 * an exact number of bytes have already been delivered:
 *
 *   SEALMARK_READFAIL_PATH   absolute path of the file whose reads fail
 *   SEALMARK_READFAIL_AFTER  number of bytes that may be delivered first;
 *                            every subsequent read() on that file returns -1
 *                            with errno = EIO
 *
 * The file is opened completely normally (open/openat are not interposed),
 * so it is a genuine "opened successfully, then read() failed part way
 * through" situation rather than an open-time or permission failure.
 *
 * The target is identified by (st_dev, st_ino), so every other fd the
 * process reads -- the dynamic loader, OpenSSL, config files, other test
 * files -- is passed through untouched. When SEALMARK_READFAIL_AFTER is not
 * set the interposed functions are pure pass-throughs, which lets the same
 * preloaded library back the control tests that exercise normal EOF.
 *
 * libstdc++'s filebuf reads with the fortified __read_chk() alias when
 * _FORTIFY_SOURCE is enabled and plain read() otherwise, so both are
 * interposed. The implementation makes no file writes.
 */

#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

typedef ssize_t (*read_fn_t)(int fd, void *buf, size_t nbytes);
typedef ssize_t (*read_chk_fn_t)(int fd, void *buf, size_t nbytes,
                                 size_t buflen);

struct target {
    int valid;
    dev_t dev;
    ino_t ino;
    long remaining;  /* bytes still deliverable; <0 = injector disabled */
    int failing;     /* once set, the next target read fails */
};

/*
 * Resolved once, on the first interposed read. dlsym() is deferred to that
 * point too: calling it from a constructor would itself be legal, but lazy
 * resolution keeps process startup identical to an un-preloaded run.
 */
static struct target g_target = {0, 0, 0, -1, 0};
static read_fn_t g_real_read;
static read_chk_fn_t g_real_read_chk;

static void initialize(void) {
    const char *after = getenv("SEALMARK_READFAIL_AFTER");
    if (after != NULL && after[0] != '\0') {
        g_target.remaining = strtol(after, NULL, 10);
    }

    const char *path = getenv("SEALMARK_READFAIL_PATH");
    if (path != NULL && g_target.remaining >= 0) {
        struct stat st;
        if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
            g_target.dev = st.st_dev;
            g_target.ino = st.st_ino;
            g_target.valid = 1;
        }
    }

    g_real_read = (read_fn_t)dlsym(RTLD_NEXT, "read");
    g_real_read_chk = (read_chk_fn_t)dlsym(RTLD_NEXT, "__read_chk");
}

static int fd_is_target(int fd) {
    if (!g_target.valid) {
        return 0;
    }
    struct stat st;
    return fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
           st.st_dev == g_target.dev && st.st_ino == g_target.ino;
}

static ssize_t filter_read(int fd, void *buf, size_t nbytes, read_fn_t real) {
    /*
     * Disabled, or a read on some unrelated fd: behave exactly like libc.
     * fstat is only paid on target fds while the injector is enabled.
     */
    if (g_target.remaining < 0 || !fd_is_target(fd)) {
        return real(fd, buf, nbytes);
    }

    if (g_target.failing) {
        errno = EIO;
        return -1;
    }

    /*
     * Deliver at most the bytes of the pre-failure budget in this call.
     * More bytes are available in the file, so a plain read() of the
     * clipped length returns exactly that many and failure begins on the
     * following call -- the caller has genuinely received partial data.
     */
    if ((long)nbytes > g_target.remaining) {
        nbytes = (size_t)g_target.remaining;
    }

    ssize_t got = real(fd, buf, nbytes);
    if (got > 0) {
        g_target.remaining -= got;
        if (g_target.remaining == 0) {
            g_target.failing = 1;
        }
    }
    return got;
}

ssize_t read(int fd, void *buf, size_t nbytes) {
    if (g_real_read == NULL) {
        initialize();
    }
    if (g_real_read == NULL) {
        /* dlsym itself failed; there is no safe way to call libc read. */
        errno = ENOSYS;
        return -1;
    }
    return filter_read(fd, buf, nbytes, g_real_read);
}

static ssize_t call_real_read_chk(int fd, void *buf, size_t nbytes) {
    /* nbytes == buflen always satisfies the fortify bounds check. */
    return g_real_read_chk(fd, buf, nbytes, nbytes);
}

ssize_t __read_chk(int fd, void *buf, size_t nbytes, size_t buflen) {
    if (g_real_read_chk == NULL) {
        initialize();
    }
    if (buflen < nbytes) {
        /* Mirror glibc's own fortify abort condition. */
        errno = EINVAL;
        return -1;
    }
    if (g_real_read_chk == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return filter_read(fd, buf, nbytes, call_real_read_chk);
}
