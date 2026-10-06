/*
 * Deterministic read-interrupt (EINTR) injector for the sealmark test-suite.
 *
 * Loaded through LD_PRELOAD (Linux), this interposes the libc read entry
 * points and replays a scripted schedule on the reads of *one specific
 * regular file*, so the "read() was interrupted by a signal but the file is
 * still perfectly readable" situation can be exercised without signals,
 * threads or timing:
 *
 *   SEALMARK_EINTR_PATH      absolute path of the file whose reads follow
 *                            the schedule
 *   SEALMARK_EINTR_SCHEDULE  comma-separated per-read directives, consumed
 *                            one per read() on the target file:
 *                              E     return -1 with errno = EINTR (no data)
 *                              S<n>  short read: deliver at most <n> bytes
 *                              F     return -1 with errno = EIO from this
 *                                    call onward (a genuine I/O error)
 *   SEALMARK_EINTR_STATS     optional path of a file the injector rewrites
 *                            at process exit with three decimal counters:
 *                            "<eintr injected> <target reads> <directives
 *                            consumed>" -- the tests use it to prove the
 *                            scripted interrupts really happened instead of
 *                            passing on a schedule that never fired.
 *
 * Once the schedule is exhausted the interposed reads are pure pass-throughs,
 * so the file is read to normal EOF afterwards. The file is opened completely
 * normally (open/openat are not interposed): this is a genuine "opened
 * successfully, then read() reported EINTR one or more times and later
 * resumed" situation, not an open-time failure.
 *
 * The target is identified by (st_dev, st_ino), so every other fd the
 * process reads -- the dynamic loader, OpenSSL, config files, other test
 * files -- is passed through untouched. When SEALMARK_EINTR_SCHEDULE is not
 * set the interposed functions are pure pass-throughs, which lets the same
 * preloaded library back the control tests that exercise normal reads.
 *
 * libstdc++'s filebuf reads with the fortified __read_chk() alias when
 * _FORTIFY_SOURCE is enabled and plain read() otherwise, so both are
 * interposed. The only file the injector itself writes is the optional
 * stats file; the target file is never modified.
 */

#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

typedef ssize_t (*read_fn_t)(int fd, void *buf, size_t nbytes);
typedef ssize_t (*read_chk_fn_t)(int fd, void *buf, size_t nbytes,
                                 size_t buflen);

enum directive_kind {
    DIR_EINTR,  /* interrupt this read: -1/EINTR, no bytes delivered */
    DIR_SHORT,  /* clip this read to param bytes at most */
    DIR_EIO     /* genuine I/O error from this read onward */
};

struct directive {
    int kind;
    long param;  /* DIR_SHORT only: maximum bytes this read may deliver */
};

#define MAX_DIRECTIVES 128

static struct {
    int valid;
    dev_t dev;
    ino_t ino;
    struct directive directives[MAX_DIRECTIVES];
    size_t directive_count;
    size_t next;                 /* next directive to apply */
    int stuck_eio;               /* a DIR_EIO directive has fired */
    unsigned long eintr_injected;
    unsigned long target_reads;
} g_target = {0, 0, 0, {{0, 0}}, 0, 0, 0, 0, 0};

/*
 * Resolved once, on the first interposed read. dlsym() is deferred to that
 * point too: calling it from a constructor would itself be legal, but lazy
 * resolution keeps process startup identical to an un-preloaded run.
 */
static read_fn_t g_real_read;
static read_chk_fn_t g_real_read_chk;
static char g_stats_path[4096];
static int g_have_stats_path;

static void parse_schedule(const char *schedule) {
    char *copy = strdup(schedule);
    if (copy == NULL) {
        return;
    }
    for (char *tok = strtok(copy, ","); tok != NULL &&
         g_target.directive_count < MAX_DIRECTIVES;
         tok = strtok(NULL, ",")) {
        struct directive d = {0, 0};
        if (tok[0] == 'E' && tok[1] == '\0') {
            d.kind = DIR_EINTR;
        } else if (tok[0] == 'F' && tok[1] == '\0') {
            d.kind = DIR_EIO;
        } else if (tok[0] == 'S' && tok[1] >= '1' && tok[1] <= '9') {
            d.kind = DIR_SHORT;
            d.param = strtol(tok + 1, NULL, 10);
            if (d.param <= 0) {
                continue;  /* a zero-byte "short read" would fake EOF */
            }
        } else {
            continue;  /* unknown token: ignore rather than misfire */
        }
        g_target.directives[g_target.directive_count++] = d;
    }
    free(copy);
}

static void initialize(void) {
    const char *schedule = getenv("SEALMARK_EINTR_SCHEDULE");
    if (schedule != NULL && schedule[0] != '\0') {
        parse_schedule(schedule);
    }

    const char *path = getenv("SEALMARK_EINTR_PATH");
    if (path != NULL && g_target.directive_count > 0) {
        struct stat st;
        if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
            g_target.dev = st.st_dev;
            g_target.ino = st.st_ino;
            g_target.valid = 1;
        }
    }

    const char *stats = getenv("SEALMARK_EINTR_STATS");
    if (stats != NULL && stats[0] != '\0') {
        size_t len = strlen(stats);
        if (len < sizeof(g_stats_path)) {
            memcpy(g_stats_path, stats, len + 1);
            g_have_stats_path = 1;
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
    if (!fd_is_target(fd)) {
        return real(fd, buf, nbytes);
    }

    g_target.target_reads++;

    if (g_target.stuck_eio) {
        errno = EIO;
        return -1;
    }

    if (g_target.next < g_target.directive_count) {
        struct directive d = g_target.directives[g_target.next++];
        switch (d.kind) {
        case DIR_EINTR:
            /*
             * A signal arrived before any data could be transferred: the
             * kernel reports -1/EINTR and the file position is unchanged,
             * so the next read sees exactly the same bytes.
             */
            g_target.eintr_injected++;
            errno = EINTR;
            return -1;
        case DIR_SHORT:
            /* Fewer bytes than requested, but more remain in the file:
             * not EOF. The caller must keep reading. */
            if ((size_t)d.param < nbytes) {
                nbytes = (size_t)d.param;
            }
            return real(fd, buf, nbytes);
        case DIR_EIO:
            g_target.stuck_eio = 1;
            errno = EIO;
            return -1;
        }
    }

    return real(fd, buf, nbytes);
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
 * At process exit, record how the schedule actually played out so the test
 * can assert the interrupts were genuinely injected (and the schedule fully
 * consumed) instead of silently passing on a preload that never fired.
 */
__attribute__((destructor))
static void write_stats(void) {
    if (!g_have_stats_path) {
        return;
    }
    int fd = open(g_stats_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        return;
    }
    char buf[128];
    int len = snprintf(buf, sizeof(buf), "%lu %lu %lu\n",
                       g_target.eintr_injected, g_target.target_reads,
                       (unsigned long)g_target.next);
    if (len > 0) {
        ssize_t unused = write(fd, buf, (size_t)len);
        (void)unused;
    }
    close(fd);
}
