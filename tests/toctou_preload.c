/*
 * Deterministic check/open (TOCTOU) fault injector for the sealmark suite.
 *
 * The input rule under test is "the object *actually opened* must be a
 * regular file": a correct implementation opens first and decides the type
 * with fstat() on the returned descriptor. A vulnerable implementation
 * instead calls a path-based stat()/filesystem status check first and only
 * then opens the path -- leaving a window in which the path can be swapped
 * from a regular file to a FIFO between the two actions.
 *
 * Real race windows cannot be staged reliably from a test, so this preload
 * makes the window permanent and deterministic: for one target path every
 * path-based status call (stat / lstat / fstatat / statx, modern glibc and
 * the legacy __-versioned entry points) is rewritten to report the object as
 * a regular file, whatever it really is. open() is deliberately NOT
 * interposed, so it still opens the genuine object -- a FIFO. fstat() on an
 * open descriptor is not interposed either.
 *
 * The net effect, when SEALMARK_TOCTOU_PATH names a FIFO:
 *
 *   * a stat-first program: the check sees "regular file", then open() opens
 *     the FIFO -- it blocks waiting for the other end or consumes whatever a
 *     writer pushes through it;
 *
 *   * an open-first program (the fix): the spoofed path stat is never even
 *     consulted; open() hands back the FIFO descriptor and fstat() on that
 *     descriptor truthfully reports S_IFIFO, so the input is rejected.
 *
 * The target is identified by (st_dev, st_ino) recorded up front with a real
 * stat(), so a symlink naming the FIFO is spoofed just like the FIFO itself.
 * The implementation performs no file writes.
 */

#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>

typedef int (*stat_fn_t)(const char *path, struct stat *buf);
typedef int (*lstat_fn_t)(const char *path, struct stat *buf);
typedef int (*fstatat_fn_t)(int dirfd, const char *path, struct stat *buf,
                            int flags);
typedef int (*statx_fn_t)(int dirfd, const char *path, int flags,
                          unsigned int mask, struct statx *buf);
typedef int (*stat64_fn_t)(const char *path, struct stat64 *buf);
typedef int (*lstat64_fn_t)(const char *path, struct stat64 *buf);
typedef int (*fstatat64_fn_t)(int dirfd, const char *path,
                              struct stat64 *buf, int flags);

struct target {
    int valid;
    dev_t dev;
    ino_t ino;
};

static struct target g_target = {0, 0, 0};
static stat_fn_t g_real_stat;
static lstat_fn_t g_real_lstat;
static fstatat_fn_t g_real_fstatat;
static statx_fn_t g_real_statx;
static stat64_fn_t g_real_stat64;
static lstat64_fn_t g_real_lstat64;
static fstatat64_fn_t g_real_fstatat64;
static int g_initialized;

static void initialize(void) {
    if (g_initialized) {
        return;
    }
    g_initialized = 1;

    g_real_stat = (stat_fn_t)dlsym(RTLD_NEXT, "stat");
    g_real_lstat = (lstat_fn_t)dlsym(RTLD_NEXT, "lstat");
    g_real_fstatat = (fstatat_fn_t)dlsym(RTLD_NEXT, "fstatat");
    g_real_statx = (statx_fn_t)dlsym(RTLD_NEXT, "statx");
    g_real_stat64 = (stat64_fn_t)dlsym(RTLD_NEXT, "stat64");
    g_real_lstat64 = (lstat64_fn_t)dlsym(RTLD_NEXT, "lstat64");
    g_real_fstatat64 = (fstatat64_fn_t)dlsym(RTLD_NEXT, "fstatat64");

    const char *path = getenv("SEALMARK_TOCTOU_PATH");
    if (path != NULL && path[0] != '\0' && g_real_stat != NULL) {
        struct stat st;
        if (g_real_stat(path, &st) == 0 && S_ISFIFO(st.st_mode)) {
            g_target.dev = st.st_dev;
            g_target.ino = st.st_ino;
            g_target.valid = 1;
        }
    }
}

static int is_target(dev_t dev, ino_t ino) {
    return g_target.valid && dev == g_target.dev && ino == g_target.ino;
}

/* Rewrites a stat buffer for the target to claim "regular file"; every
 * other field is left untouched. Returns 1 when it rewrote the buffer. */
static int masquerade_as_regular(struct stat *st) {
    if (!is_target(st->st_dev, st->st_ino)) {
        return 0;
    }
    st->st_mode = (st->st_mode & ~S_IFMT) | S_IFREG;
    return 1;
}

static int masquerade64_as_regular(struct stat64 *st) {
    if (!is_target(st->st_dev, st->st_ino)) {
        return 0;
    }
    st->st_mode = (st->st_mode & ~S_IFMT) | S_IFREG;
    return 1;
}

int stat(const char *path, struct stat *buf) {
    initialize();
    if (g_real_stat == NULL) {
        errno = ENOSYS;
        return -1;
    }
    int rc = g_real_stat(path, buf);
    if (rc == 0) {
        masquerade_as_regular(buf);
    }
    return rc;
}

int lstat(const char *path, struct stat *buf) {
    initialize();
    if (g_real_lstat == NULL) {
        errno = ENOSYS;
        return -1;
    }
    int rc = g_real_lstat(path, buf);
    if (rc == 0) {
        masquerade_as_regular(buf);
    }
    return rc;
}

int fstatat(int dirfd, const char *path, struct stat *buf, int flags) {
    initialize();
    if (g_real_fstatat == NULL) {
        errno = ENOSYS;
        return -1;
    }
    int rc = g_real_fstatat(dirfd, path, buf, flags);
    if (rc == 0) {
        masquerade_as_regular(buf);
    }
    return rc;
}

/*
 * The _FILE_OFFSET_BITS=64 spellings are separate *symbol names* in glibc
 * (stat64 / lstat64 / fstatat64), not aliases reached through interposition
 * of stat/fstatat. Static-PIE callers such as the CPython used by the test's
 * liveness probe bind these names directly, so they must be interposed in
 * their own right. They carry struct stat64 buffers.
 */
int stat64(const char *path, struct stat64 *buf) {
    initialize();
    if (g_real_stat64 == NULL) {
        errno = ENOSYS;
        return -1;
    }
    int rc = g_real_stat64(path, buf);
    if (rc == 0) {
        masquerade64_as_regular(buf);
    }
    return rc;
}

int lstat64(const char *path, struct stat64 *buf) {
    initialize();
    if (g_real_lstat64 == NULL) {
        errno = ENOSYS;
        return -1;
    }
    int rc = g_real_lstat64(path, buf);
    if (rc == 0) {
        masquerade64_as_regular(buf);
    }
    return rc;
}

int fstatat64(int dirfd, const char *path, struct stat64 *buf, int flags) {
    initialize();
    if (g_real_fstatat64 == NULL) {
        errno = ENOSYS;
        return -1;
    }
    int rc = g_real_fstatat64(dirfd, path, buf, flags);
    if (rc == 0) {
        masquerade64_as_regular(buf);
    }
    return rc;
}

/* Newer glibc spells fstatat() this way; same ABI on every live platform. */
int newfstatat(int dirfd, const char *path, struct stat *buf, int flags) {
    return fstatat(dirfd, path, buf, flags);
}

int statx(int dirfd, const char *path, int flags, unsigned int mask,
          struct statx *buf) {
    initialize();
    if (g_real_statx == NULL) {
        errno = ENOSYS;
        return -1;
    }
    int rc = g_real_statx(dirfd, path, flags, mask, buf);
    if (rc == 0 && g_target.valid) {
        /* statx splits the device id into major/minor; reassemble the same
         * dev_t the target was recorded with, then match on (dev, inode). */
        dev_t dev = makedev(buf->stx_dev_major, buf->stx_dev_minor);
        if (dev == g_target.dev && buf->stx_ino == g_target.ino &&
            S_ISFIFO(buf->stx_mode)) {
            buf->stx_mode = (buf->stx_mode & ~S_IFMT) | S_IFREG;
        }
    }
    return rc;
}
