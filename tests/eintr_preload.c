/*
 * Deterministic read-interruption injector for the sealmark test-suite.
 *
 * Loaded through LD_PRELOAD (Linux), this interposes the libc read entry
 * points and makes reads of *one specific regular file* misbehave in
 * controlled, combinable ways:
 *
 *   SEALMARK_EINTR_PATH       absolute path of the file to intercept
 *   SEALMARK_EINTR_AT         start injecting once this many bytes have been
 *                             delivered from the file (default 0, i.e. before
 *                             the very first byte)
 *   SEALMARK_EINTR_TIMES      number of consecutive read() calls that return
 *                             -1 with errno = EINTR once the AT position is
 *                             reached (default 0: no interrupts)
 *   SEALMARK_EINTR_SHORT      clip every successful read of the target to at
 *                             most this many bytes, even though more content
 *                             remains (default 0: no clipping)
 *   SEALMARK_EINTR_EIO_AFTER  once this many bytes have been delivered (and
 *                             any interrupts are exhausted), every further
 *                             read of the target fails with EIO
 *                             (default: never)
 *   SEALMARK_EINTR_REPORT     optional path to a counters file written at
 *                             process exit, so tests can prove the staged
 *                             conditions genuinely occurred
 *
 * The file is opened completely normally (open/openat are not interposed),
 * so these are genuine "opened successfully, then read() was interrupted /
 * returned short / failed" situations rather than open-time failures.
 *
 * The target is identified by (st_dev, st_ino), so every other fd the
 * process reads -- the dynamic loader, OpenSSL, config files, other test
 * files -- is passed through untouched. With none of TIMES/SHORT/EIO_AFTER
 * set the interposed functions are pure pass-throughs, which lets the same
 * preloaded library back the control tests that exercise normal reads.
 *
 * libstdc++'s filebuf reads with the fortified __read_chk() alias when
 * _FORTIFY_SOURCE is enabled and plain read() otherwise, so both are
 * interposed. The implementation makes no file writes except the optional
 * report file at exit.
 */

#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

typedef ssize_t (*read_fn_t)(int fd, void *buf, size_t nbytes);
typedef ssize_t (*read_chk_fn_t)(int fd, void *buf, size_t nbytes,
                                 size_t buflen);

static struct injector {
    int armed;       /* target path resolved to a regular file */
    dev_t dev;
    ino_t ino;
    long at;           /* deliver at least this many bytes before EINTRs */
    long eintr_left;   /* interrupts still to inject */
    long short_max;    /* >0: clip each read to this many bytes */
    long eio_after;    /* >=0: fail with EIO once delivered reaches this */
    long delivered;    /* total bytes handed to the caller so far */
    long eintr_pos;    /* delivered count at the first EINTR, -1 if none */
    long n_reads;      /* target read() calls seen */
    long n_eintr;      /* EINTR results injected */
    long n_eio;        /* EIO results injected */
    long n_short;      /* reads clipped to the short size */
} g = {0, 0, 0, 0, 0, 0, -1, 0, -1, 0, 0, 0, 0};

static char g_report_path[4096]; /* empty = no report requested */

/*
 * Resolved once, on the first interposed read. dlsym() is deferred to that
 * point too: calling it from a constructor would itself be legal, but lazy
 * resolution keeps process startup identical to an un-preloaded run.
 */
static read_fn_t g_real_read;
static read_chk_fn_t g_real_read_chk;

static long env_long(const char *name, long fallback) {
    const char *value = getenv(name);
    if (value == NULL || value[0] == '\0') {
        return fallback;
    }
    return strtol(value, NULL, 10);
}

static void initialize(void) {
    g.at = env_long("SEALMARK_EINTR_AT", 0);
    g.eintr_left = env_long("SEALMARK_EINTR_TIMES", 0);
    g.short_max = env_long("SEALMARK_EINTR_SHORT", 0);
    g.eio_after = env_long("SEALMARK_EINTR_EIO_AFTER", -1);

    const char *report = getenv("SEALMARK_EINTR_REPORT");
    if (report != NULL && report[0] != '\0') {
        snprintf(g_report_path, sizeof(g_report_path), "%s", report);
    }

    const char *path = getenv("SEALMARK_EINTR_PATH");
    if (path != NULL && path[0] != '\0') {
        struct stat st;
        if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
            g.dev = st.st_dev;
            g.ino = st.st_ino;
            g.armed = 1;
        }
    }

    g_real_read = (read_fn_t)dlsym(RTLD_NEXT, "read");
    g_real_read_chk = (read_chk_fn_t)dlsym(RTLD_NEXT, "__read_chk");
}

static int fd_is_target(int fd) {
    if (!g.armed) {
        return 0;
    }
    struct stat st;
    return fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
           st.st_dev == g.dev && st.st_ino == g.ino;
}

static ssize_t filter_read(int fd, void *buf, size_t nbytes, read_fn_t real) {
    /*
     * Not armed, or a read on some unrelated fd: behave exactly like libc.
     * fstat is only paid on target fds while the injector is armed.
     */
    if (!fd_is_target(fd)) {
        return real(fd, buf, nbytes);
    }

    g.n_reads++;

    /*
     * A system call interrupted before transferring data: no bytes are
     * delivered and the caller is expected to retry. Fires once the
     * configured position has been reached, TIMES times in a row.
     */
    if (g.eintr_left > 0 && g.delivered >= g.at) {
        g.eintr_left--;
        g.n_eintr++;
        if (g.eintr_pos < 0) {
            g.eintr_pos = g.delivered;
        }
        errno = EINTR;
        return -1;
    }

    /*
     * A genuine I/O error after the interrupts: distinct from both EINTR
     * (transient) and EOF (normal), and fatal to the caller.
     */
    if (g.eio_after >= 0 && g.delivered >= g.eio_after) {
        g.n_eio++;
        errno = EIO;
        return -1;
    }

    /*
     * A short read: fewer bytes than requested even though the file has
     * more content. Legal for read() and must not be mistaken for EOF.
     */
    if (g.short_max > 0 && (long)nbytes > g.short_max) {
        nbytes = (size_t)g.short_max;
        g.n_short++;
    }

    ssize_t got = real(fd, buf, nbytes);
    if (got > 0) {
        g.delivered += got;
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

/*
 * Counter dump for the tests: proves the staged interrupts/short reads/I/O
 * error actually fired (a digest that matches with or without injection
 * cannot show that on its own). Written at process exit so every read of
 * the run is accounted for.
 */
__attribute__((destructor))
static void write_report(void) {
    if (g_report_path[0] == '\0') {
        return;
    }
    int fd = open(g_report_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        return;
    }
    char buf[512];
    int len = snprintf(buf, sizeof(buf),
                       "reads=%ld\neintr=%ld\neio=%ld\nshort=%ld\n"
                       "delivered=%ld\neintr_pos=%ld\n",
                       g.n_reads, g.n_eintr, g.n_eio, g.n_short,
                       g.delivered, g.eintr_pos);
    if (len > 0) {
        ssize_t written = write(fd, buf, (size_t)len);
        (void)written;
    }
    close(fd);
}
