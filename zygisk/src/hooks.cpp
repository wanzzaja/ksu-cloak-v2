#include "hooks.hpp"
#include "config.hpp"
#include "zygisk.hpp"

#include <android/log.h>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <link.h>
#include <pthread.h>
#include <string>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#define LOG_TAG "KSUCloak"
#define LOGI(...) ((void)0)

namespace cloak {
namespace {

bool is_hidden(const char *path) {
    if (!path) return false;
    for (const char *p : kHiddenPaths) if (strstr(path, p)) return true;
    for (const char *kw : kHiddenKeywords)
        for (const char *p = path; *p; ++p) {
            size_t n = strlen(kw);
            if (strncasecmp(p, kw, n) == 0) return true;
        }
    return false;
}

bool is_hidden_prop(const char *name) {
    if (!name) return false;
    for (const char *p : kHiddenProps) if (strcmp(name, p) == 0) return true;
    return false;
}

const char *spoof_lookup(const char *name) {
    if (!name) return nullptr;
    for (auto &pair : kSpoofedProps)
        if (strcmp(name, pair[0]) == 0) return pair[1];
    return nullptr;
}

bool is_filterable_proc(const char *path) {
    if (!path) return false;
    if (strncmp(path, "/proc/", 6) != 0 && strncmp(path, "/sys/", 5) != 0) return false;
    const char *p = path + (strncmp(path, "/proc/", 6) == 0 ? 6 : 5);
    if (strncmp(p, "self/", 5) == 0) p += 5;
    else if (strncmp(p, "class/", 6) == 0) p += 6;
    else if (strncmp(p, "devices/", 8) == 0) p += 8;
    else if (strncmp(p, "cpuinfo", 7) == 0) return true;
    else if (strncmp(p, "version", 7) == 0) return true;
    else if (strncmp(p, "net/", 4) == 0) return true;
    else if (strncmp(p, "sys/", 4) == 0) p += 4;
    else {
        while (*p >= '0' && *p <= '9') ++p;
        if (*p == '/') ++p;
    }
    if (strncmp(p, "task/", 5) == 0) {
        p += 5;
        while (*p >= '0' && *p <= '9') ++p;
        if (*p == '/') ++p;
    }
    if (strncmp(p, "fd/", 3) == 0) return true;

    return strcmp(p, "maps") == 0 || strcmp(p, "status") == 0 ||
           strcmp(p, "cmdline") == 0 || strcmp(p, "comm") == 0 ||
           strcmp(p, "mountinfo") == 0 || strcmp(p, "mounts") == 0 ||
           strcmp(p, "cgroup") == 0 || strcmp(p, "version") == 0 ||
           strcmp(p, "mem") == 0 || strcmp(p, "tcp") == 0 || strcmp(p, "unix") == 0 ||
           strcmp(p, "smaps") == 0 || strcmp(p, "smaps_rollup") == 0 ||
           strcmp(p, "numa_maps") == 0 || strcmp(p, "pagemap") == 0 ||
           strcmp(p, "syscall") == 0 ||
           strcmp(p, "serial_number") == 0 || strcmp(p, "machine") == 0 ||
           strstr(p, "wlan0/address") || strstr(p, "eth0/address") ||
           strstr(p, "bt-pan/address") || strstr(p, "iSerial") ||
           strstr(p, "f_serial/serial") || strstr(p, "boot_id") ||
           strstr(p, "/proc/cpuinfo");
}

std::string slurp_fd(int fd) {
    std::string out;
    lseek(fd, 0, SEEK_SET);
    char buf[4096];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) out.append(buf, n);
    return out;
}

void filter_lines(std::string &s) {
    std::string out;
    out.reserve(s.size());
    size_t i = 0;
    while (i < s.size()) {
        size_t e = s.find('\n', i);
        if (e == std::string::npos) e = s.size();
        bool hide = false;
        for (const char *kw : kHiddenKeywords) {
            size_t n = strlen(kw);
            for (size_t k = i; k + n <= e; ++k) {
                if (strncasecmp(s.data() + k, kw, n) == 0) { hide = true; break; }
            }
            if (hide) break;
        }
        if (!hide) out.append(s, i, e - i + (e < s.size() ? 1 : 0));
        i = e + 1;
    }
    s.swap(out);
}

void filter_sockets(std::string &s) {
    std::string out;
    out.reserve(s.size());
    size_t i = 0;
    while (i < s.size()) {
        size_t e = s.find('\n', i);
        if (e == std::string::npos) e = s.size();
        bool hide = false;
        for (const char *kw : kSuspiciousSockets) {
            size_t n = strlen(kw);
            for (size_t k = i; k + n <= e; ++k) {
                if (strncasecmp(s.data() + k, kw, n) == 0) { hide = true; break; }
            }
            if (hide) break;
        }
        if (!hide) out.append(s, i, e - i + (e < s.size() ? 1 : 0));
        i = e + 1;
    }
    s.swap(out);
}

void filter_status(std::string &s) {
    std::string out;
    out.reserve(s.size());
    size_t i = 0;
    while (i < s.size()) {
        size_t e = s.find('\n', i);
        if (e == std::string::npos) e = s.size();
        if (e - i >= 9 && strncmp(s.data() + i, "TracerPid", 9) == 0) {
            out += "TracerPid:\t0\n";
        } else if (e - i >= 5 && strncmp(s.data() + i, "Name:", 5) == 0) {
            out += "Name:\t" + std::string(kSafeThreadName) + "\n";
        } else {
            out.append(s, i, e - i + (e < s.size() ? 1 : 0));
        }
        i = e + 1;
    }
    s.swap(out);
}

void filter_proc(const char *path, std::string &content) {
    if (strstr(path, "maps") || strstr(path, "mountinfo") || strstr(path, "mounts") ||
        strstr(path, "smaps") || strstr(path, "smaps_rollup") ||
        strstr(path, "numa_maps") || strstr(path, "pagemap")) {
        filter_lines(content);
    } else if (strstr(path, "status")) {
        filter_status(content);
    } else if (strstr(path, "tcp") || strstr(path, "unix")) {
        filter_sockets(content);
    } else if (strstr(path, "cmdline")) {
        for (const char *kw : kHiddenKeywords) {
            size_t klen = strlen(kw);
            size_t pos = 0;
            while ((pos = content.find(kw, pos)) != std::string::npos) {
                content.replace(pos, klen, "system");
                pos += 6;
            }
        }
    } else if (strstr(path, "comm")) {
        for (const char *kw : kSuspiciousThreadNames)
            if (strstr(content.c_str(), kw)) { content = std::string(kSafeThreadName) + "\n"; break; }
    }
}

int make_filtered_fd(const std::string &content) {
    int fd = memfd_create("cls", MFD_CLOEXEC);
    if (fd < 0) return -1;
    if (write(fd, content.data(), content.size()) < 0) { close(fd); return -1; }
    lseek(fd, 0, SEEK_SET);
    return fd;
}

FILE *make_filtered_stream(const std::string &content, const char *mode) {
    int fd = make_filtered_fd(content);
    if (fd < 0) return nullptr;
    FILE *f = fdopen(fd, mode);
    if (!f) close(fd);
    return f;
}

int      (*orig_open)(const char *, int, ...)                   = nullptr;
int      (*orig_openat)(int, const char *, int, ...)            = nullptr;
int      (*orig_open64)(const char *, int, ...)                 = nullptr;
int      (*orig_openat64)(int, const char *, int, ...)          = nullptr;
int      (*orig___open_2)(const char *, int)                    = nullptr;
int      (*orig___openat_2)(int, const char *, int)             = nullptr;
int      (*orig_stat)(const char *, struct stat *)              = nullptr;
int      (*orig_lstat)(const char *, struct stat *)             = nullptr;
int      (*orig_fstatat)(int, const char *, struct stat *, int) = nullptr;
int      (*orig_access)(const char *, int)                      = nullptr;
int      (*orig_faccessat)(int, const char *, int, int)         = nullptr;
ssize_t  (*orig_readlink)(const char *, char *, size_t)         = nullptr;
ssize_t  (*orig_readlinkat)(int, const char *, char *, size_t)  = nullptr;
DIR     *(*orig_opendir)(const char *)                          = nullptr;
FILE    *(*orig_fopen)(const char *, const char *)              = nullptr;
FILE    *(*orig_fopen64)(const char *, const char *)            = nullptr;
int      (*orig___system_property_get)(const char *, char *)    = nullptr;
const void *(*orig___system_property_find)(const char *)        = nullptr;
void     (*orig___system_property_read_callback)(const void *, void (*)(void*, const char*, const char*, unsigned), void *) = nullptr;
long     (*orig_syscall)(long, ...)                             = nullptr;
int      (*orig_dl_iterate_phdr)(int (*)(struct dl_phdr_info *, size_t, void *), void *) = nullptr;
void    *(*orig_dlopen)(const char *, int)                      = nullptr;
void    *(*orig_dlsym)(void *, const char *)                    = nullptr;
int      (*orig_ioctl)(int, unsigned long, ...)                 = nullptr;
int      (*orig_pthread_setname_np)(pthread_t, const char *)    = nullptr;
int      (*orig_prctl)(int, unsigned long, unsigned long, unsigned long, unsigned long) = nullptr;
long     (*orig_ptrace)(int, pid_t, void *, void *)             = nullptr;
ssize_t  (*orig_process_vm_readv)(pid_t, const struct iovec *, unsigned long, const struct iovec *, unsigned long, unsigned long) = nullptr;
ssize_t  (*orig_process_vm_writev)(pid_t, const struct iovec *, unsigned long, const struct iovec *, unsigned long, unsigned long) = nullptr;
int      (*orig_statx)(int, const char *, int, unsigned int, struct statx *) = nullptr;
ssize_t  (*orig_getdents64)(int, void *, size_t)                 = nullptr;

int hook_open(const char *p, int f, ...) {
    if (is_hidden(p)) { errno = ENOENT; return -1; }
    mode_t m = 0;
    if (f & (O_CREAT | O_TMPFILE)) { va_list a; va_start(a,f); m=va_arg(a,mode_t); va_end(a); }
    if (is_filterable_proc(p) && (f & O_ACCMODE) == O_RDONLY) {
        int real = orig_open(p, f, m);
        if (real < 0) return real;
        std::string c = slurp_fd(real);
        close(real);
        filter_proc(p, c);
        return make_filtered_fd(c);
    }
    return orig_open(p, f, m);
}

int hook_openat(int d, const char *p, int f, ...) {
    if (is_hidden(p)) { errno = ENOENT; return -1; }
    mode_t m = 0;
    if (f & (O_CREAT | O_TMPFILE)) { va_list a; va_start(a,f); m=va_arg(a,mode_t); va_end(a); }
    if (is_filterable_proc(p) && (f & O_ACCMODE) == O_RDONLY) {
        int real = orig_openat(d, p, f, m);
        if (real < 0) return real;
        std::string c = slurp_fd(real);
        close(real);
        filter_proc(p, c);
        return make_filtered_fd(c);
    }
    return orig_openat(d, p, f, m);
}

int hook_open64(const char *p, int f, ...) {
    if (is_hidden(p)) { errno = ENOENT; return -1; }
    mode_t m = 0;
    if (f & (O_CREAT | O_TMPFILE)) { va_list a; va_start(a,f); m=va_arg(a,mode_t); va_end(a); }
    return orig_open64(p, f, m);
}

int hook_openat64(int d, const char *p, int f, ...) {
    if (is_hidden(p)) { errno = ENOENT; return -1; }
    mode_t m = 0;
    if (f & (O_CREAT | O_TMPFILE)) { va_list a; va_start(a,f); m=va_arg(a,mode_t); va_end(a); }
    return orig_openat64(d, p, f, m);
}

int hook___open_2(const char *p, int f) { if (is_hidden(p)) { errno=ENOENT; return -1; } return orig___open_2(p,f); }
int hook___openat_2(int d, const char *p, int f) { if (is_hidden(p)) { errno=ENOENT; return -1; } return orig___openat_2(d,p,f); }
int hook_stat(const char *p, struct stat *b) { if (is_hidden(p)) { errno=ENOENT; return -1; } return orig_stat(p,b); }
int hook_lstat(const char *p, struct stat *b) { if (is_hidden(p)) { errno=ENOENT; return -1; } return orig_lstat(p,b); }
int hook_fstatat(int d, const char *p, struct stat *b, int f) { if (is_hidden(p)) { errno=ENOENT; return -1; } return orig_fstatat(d,p,b,f); }
int hook_access(const char *p, int m) { if (is_hidden(p)) { errno=ENOENT; return -1; } return orig_access(p,m); }
int hook_faccessat(int d, const char *p, int m, int f) { if (is_hidden(p)) { errno=ENOENT; return -1; } return orig_faccessat(d,p,m,f); }

ssize_t hook_readlink(const char *p, char *b, size_t s) {
    if (is_hidden(p)) { errno = ENOENT; return -1; }
    ssize_t res = orig_readlink(p, b, s);
    if (res > 0 && strstr(p, "/proc/self/fd/")) {
        if (is_hidden(b) || strstr(b, "memfd:") || strstr(b, "jit-cache")) {
            strncpy(b, "/dev/null", s);
            return strlen(b);
        }
    }
    return res;
}

ssize_t hook_readlinkat(int d, const char *p, char *b, size_t s) {
    if (is_hidden(p)) { errno = ENOENT; return -1; }
    ssize_t res = orig_readlinkat(d, p, b, s);
    if (res > 0 && strstr(p, "/proc/self/fd/")) {
        if (is_hidden(b) || strstr(b, "memfd:") || strstr(b, "jit-cache")) {
            strncpy(b, "/dev/null", s);
            return strlen(b);
        }
    }
    return res;
}

DIR *hook_opendir(const char *p) { if (is_hidden(p)) { errno=ENOENT; return nullptr; } return orig_opendir(p); }

FILE *hook_fopen(const char *p, const char *m) {
    if (is_hidden(p)) { errno=ENOENT; return nullptr; }
    if (is_filterable_proc(p) && m && m[0] == 'r') {
        FILE *real = orig_fopen(p, m);
        if (!real) return nullptr;
        std::string c;
        char buf[4096]; size_t n;
        while ((n = fread(buf, 1, sizeof(buf), real)) > 0) c.append(buf, n);
        fclose(real);
        filter_proc(p, c);
        return make_filtered_stream(c, "r");
    }
    return orig_fopen(p, m);
}

FILE *hook_fopen64(const char *p, const char *m) {
    if (is_hidden(p)) { errno=ENOENT; return nullptr; }
    return orig_fopen64(p, m);
}

int hook___system_property_get(const char *n, char *v) {
    const char *s = spoof_lookup(n);
    if (s) { strcpy(v, s); return (int)strlen(s); }
    if (is_hidden_prop(n)) { v[0] = 0; return 0; }
    return orig___system_property_get(n, v);
}

const void *hook___system_property_find(const char *n) {
    if (is_hidden_prop(n)) return nullptr;
    return orig___system_property_find(n);
}

struct prop_ctx {
    void (*user_cb)(void*, const char*, const char*, unsigned);
    void *user_cookie;
};

void prop_inner_cb(void *cookie, const char *name, const char *value, unsigned serial) {
    auto *c = static_cast<prop_ctx*>(cookie);
    const char *spoofed = spoof_lookup(name);
    if (spoofed) { c->user_cb(c->user_cookie, name, spoofed, serial); return; }
    if (is_hidden_prop(name)) return;
    c->user_cb(c->user_cookie, name, value, serial);
}

void hook___system_property_read_callback(const void *pi,
        void (*cb)(void*, const char*, const char*, unsigned), void *cookie) {
    prop_ctx c{ cb, cookie };
    orig___system_property_read_callback(pi, prop_inner_cb, &c);
}

long hook_syscall(long number, ...) {
    va_list ap; va_start(ap, number);
    long a1 = va_arg(ap, long); long a2 = va_arg(ap, long); long a3 = va_arg(ap, long);
    long a4 = va_arg(ap, long); long a5 = va_arg(ap, long); long a6 = va_arg(ap, long);
    va_end(ap);

    if (number == SYS_openat || number == SYS_readlinkat || number == SYS_newfstatat
#ifdef SYS_openat2
        || number == SYS_openat2
#endif
    ) {
        const char *path = (const char*)a2;
        if (is_hidden(path)) { errno = ENOENT; return -1; }
    }

    return orig_syscall(number, a1, a2, a3, a4, a5, a6);
}

struct dl_ctx {
    int (*user_cb)(struct dl_phdr_info *, size_t, void *);
    void *user_data;
};

int dl_inner_cb(struct dl_phdr_info *info, size_t size, void *data) {
    auto *c = static_cast<dl_ctx*>(data);
    if (info->dlpi_name && is_hidden(info->dlpi_name)) return 0;
    return c->user_cb(info, size, c->user_data);
}

int hook_dl_iterate_phdr(int (*cb)(struct dl_phdr_info *, size_t, void *), void *data) {
    dl_ctx c{ cb, data };
    return orig_dl_iterate_phdr(dl_inner_cb, &c);
}

void *hook_dlopen(const char *name, int flags) {
    if (name && is_hidden(name)) { errno = ENOENT; return nullptr; }
    return orig_dlopen(name, flags);
}

void *hook_dlsym(void *handle, const char *symbol) {
    if (symbol && is_hidden(symbol)) return nullptr;
    return orig_dlsym(handle, symbol);
}

int hook_ioctl(int fd, unsigned long req, ...) {
    va_list ap; va_start(ap, req); void *arg = va_arg(ap, void*); va_end(ap);
    return orig_ioctl(fd, req, arg);
}

int hook_pthread_setname_np(pthread_t thread, const char *name) {
    if (name) {
        for (const char *kw : kSuspiciousThreadNames) {
            if (strstr(name, kw)) return orig_pthread_setname_np(thread, kSafeThreadName);
        }
    }
    return orig_pthread_setname_np(thread, name);
}

int hook_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) {
    if (option == PR_SET_NAME && arg2 != 0) {
        const char *name = (const char*)arg2;
        for (const char *kw : kSuspiciousThreadNames) {
            if (strstr(name, kw)) {
                return orig_prctl(PR_SET_NAME, (unsigned long)kSafeThreadName, 0, 0, 0);
            }
        }
    }
    if (option == PR_SET_DUMPABLE) {
        return orig_prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
    return orig_prctl(option, arg2, arg3, arg4, arg5);
}

long hook_ptrace(int request, pid_t pid, void *addr, void *data) {
    if (request == PTRACE_ATTACH || request == PTRACE_SEIZE) {
        errno = EPERM;
        return -1;
    }
    if (request == PTRACE_TRACEME) {
        return 0;
    }
    return orig_ptrace(request, pid, addr, data);
}

ssize_t hook_process_vm_readv(pid_t pid, const struct iovec *local, unsigned long liovcnt,
                              const struct iovec *remote, unsigned long riovcnt,
                              unsigned long flags) {
    if (pid != getpid()) { errno = EPERM; return -1; }
    return orig_process_vm_readv(pid, local, liovcnt, remote, riovcnt, flags);
}

ssize_t hook_process_vm_writev(pid_t pid, const struct iovec *local, unsigned long liovcnt,
                               const struct iovec *remote, unsigned long riovcnt,
                               unsigned long flags) {
    if (pid != getpid()) { errno = EPERM; return -1; }
    return orig_process_vm_writev(pid, local, liovcnt, remote, riovcnt, flags);
}

int hook_statx(int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *statxbuf) {
    if (is_hidden(pathname)) { errno = ENOENT; return -1; }
    return orig_statx(dirfd, pathname, flags, mask, statxbuf);
}

ssize_t hook_getdents64(int fd, void *dirp, size_t count) {
    return orig_getdents64(fd, dirp, count);
}

bool g_installed = false;

}

void install_hooks(zygisk::Api *api) {
    if (g_installed) return;
    g_installed = true;
    if (!api || !api->pltHookRegister) return;

    api->pltHookRegister(0,0,"open",    (void*)hook_open,    (void**)&orig_open);
    api->pltHookRegister(0,0,"openat",  (void*)hook_openat,  (void**)&orig_openat);
    api->pltHookRegister(0,0,"open64",  (void*)hook_open64,  (void**)&orig_open64);
    api->pltHookRegister(0,0,"openat64",(void*)hook_openat64,(void**)&orig_openat64);
    api->pltHookRegister(0,0,"__open_2",  (void*)hook___open_2,  (void**)&orig___open_2);
    api->pltHookRegister(0,0,"__openat_2",(void*)hook___openat_2,(void**)&orig___openat_2);
    api->pltHookRegister(0,0,"stat",   (void*)hook_stat,   (void**)&orig_stat);
    api->pltHookRegister(0,0,"lstat",  (void*)hook_lstat,  (void**)&orig_lstat);
    api->pltHookRegister(0,0,"fstatat",(void*)hook_fstatat,(void**)&orig_fstatat);
    api->pltHookRegister(0,0,"access",   (void*)hook_access,   (void**)&orig_access);
    api->pltHookRegister(0,0,"faccessat",(void*)hook_faccessat,(void**)&orig_faccessat);
    api->pltHookRegister(0,0,"readlink",  (void*)hook_readlink,  (void**)&orig_readlink);
    api->pltHookRegister(0,0,"readlinkat",(void*)hook_readlinkat,(void**)&orig_readlinkat);
    api->pltHookRegister(0,0,"opendir",(void*)hook_opendir,(void**)&orig_opendir);
    api->pltHookRegister(0,0,"fopen",  (void*)hook_fopen,  (void**)&orig_fopen);
    api->pltHookRegister(0,0,"fopen64",(void*)hook_fopen64,(void**)&orig_fopen64);

    api->pltHookRegister(0,0,"__system_property_get",
        (void*)hook___system_property_get,(void**)&orig___system_property_get);
    api->pltHookRegister(0,0,"__system_property_find",
        (void*)hook___system_property_find,(void**)&orig___system_property_find);
    api->pltHookRegister(0,0,"__system_property_read_callback",
        (void*)hook___system_property_read_callback,
        (void**)&orig___system_property_read_callback);

    api->pltHookRegister(0,0,"syscall",(void*)hook_syscall,(void**)&orig_syscall);
    api->pltHookRegister(0,0,"ioctl",(void*)hook_ioctl,(void**)&orig_ioctl);
    
    // Anti-crash TikTok: Comment out 3 lines below if TikTok force closes
    api->pltHookRegister(0,0,"dl_iterate_phdr", (void*)hook_dl_iterate_phdr,(void**)&orig_dl_iterate_phdr);
    api->pltHookRegister(0,0,"dlopen",(void*)hook_dlopen,(void**)&orig_dlopen);
    api->pltHookRegister(0,0,"dlsym", (void*)hook_dlsym, (void**)&orig_dlsym);

    api->pltHookRegister(0,0,"pthread_setname_np",(void*)hook_pthread_setname_np,(void**)&orig_pthread_setname_np);
    api->pltHookRegister(0,0,"prctl",(void*)hook_prctl,(void**)&orig_prctl);
    api->pltHookRegister(0,0,"ptrace",(void*)hook_ptrace,(void**)&orig_ptrace);
    api->pltHookRegister(0,0,"process_vm_readv",(void*)hook_process_vm_readv,(void**)&orig_process_vm_readv);
    api->pltHookRegister(0,0,"process_vm_writev",(void*)hook_process_vm_writev,(void**)&orig_process_vm_writev);
    api->pltHookRegister(0,0,"statx",(void*)hook_statx,(void**)&orig_statx);
    api->pltHookRegister(0,0,"getdents64",(void*)hook_getdents64,(void**)&orig_getdents64);

    api->pltHookCommit();
}

}
