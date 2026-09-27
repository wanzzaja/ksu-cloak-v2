#include "hooks.hpp"
#include "config.hpp"
#include "zygisk.hpp"

#include <android/log.h>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <link.h>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <unistd.h>

#define LOG_TAG "KSUCloak"
static bool g_debug = false;
#define LOGI(...) do { if (g_debug) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__); } while (0)

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
    if (strncmp(path, "/proc/", 6) != 0) return false;
    const char *p = path + 6;
    if (strncmp(p, "self/", 5) == 0) p += 5;
    else {
        while (*p >= '0' && *p <= '9') ++p;
        if (*p != '/') return false;
        ++p;
    }
    if (strncmp(p, "task/", 5) == 0) {
        p += 5;
        while (*p >= '0' && *p <= '9') ++p;
        if (*p != '/') return false;
        ++p;
    }
    return strcmp(p, "maps") == 0 || strcmp(p, "status") == 0 ||
           strcmp(p, "cmdline") == 0 || strcmp(p, "comm") == 0;
}

std::string slurp_fd(int fd) {
    std::string out;
    lseek(fd, 0, SEEK_SET);
    char buf[4096];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) out.append(buf, n);
    return out;
}

void filter_maps(std::string &s) {
    std::string out;
    out.reserve(s.size());
    size_t i = 0;
    while (i < s.size()) {
        size_t e = s.find('\n', i);
        if (e == std::string::npos) e = s.size();
        bool hide = false;
        for (const char *kw : kHiddenKeywords) {
            for (size_t k = i; k + strlen(kw) <= e; ++k) {
                if (strncasecmp(s.data() + k, kw, strlen(kw)) == 0) { hide = true; break; }
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
        } else {
            out.append(s, i, e - i + (e < s.size() ? 1 : 0));
        }
        i = e + 1;
    }
    s.swap(out);
}

void filter_cmdline(std::string &s) {
    for (const char *kw : kHiddenKeywords) {
        size_t pos = 0;
        while ((pos = s.find(kw, pos)) != std::string::npos) {
            s.replace(pos, strlen(kw), "system");
        }
    }
}

void filter_proc(const char *path, std::string &content) {
    if (strstr(path, "maps")) filter_maps(content);
    else if (strstr(path, "status")) filter_status(content);
    else if (strstr(path, "cmdline")) filter_cmdline(content);
    else if (strstr(path, "comm")) {
        for (const char *kw : kSuspiciousThreadNames)
            if (strstr(content.c_str(), kw)) { content = "system\n"; break; }
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
ssize_t hook_readlink(const char *p, char *b, size_t s) { if (is_hidden(p)) { errno=ENOENT; return -1; } return orig_readlink(p,b,s); }
ssize_t hook_readlinkat(int d, const char *p, char *b, size_t s) { if (is_hidden(p)) { errno=ENOENT; return -1; } return orig_readlinkat(d,p,b,s); }
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
    va_list ap;
    va_start(ap, number);
    long a1 = va_arg(ap, long);
    long a2 = va_arg(ap, long);
    long a3 = va_arg(ap, long);
    long a4 = va_arg(ap, long);
    long a5 = va_arg(ap, long);
    long a6 = va_arg(ap, long);
    va_end(ap);

    if (number == SYS_openat) {
        const char *path = (const char*)a2;
        if (is_hidden(path)) { errno = ENOENT; return -1; }
    }
#ifdef SYS_openat2
    if (number == SYS_openat2) {
        const char *path = (const char*)a2;
        if (is_hidden(path)) { errno = ENOENT; return -1; }
    }
#endif
    if (number == SYS_faccessat || number == SYS_faccessat2) {
        const char *path = (const char*)a2;
        if (is_hidden(path)) { errno = ENOENT; return -1; }
    }
    if (number == SYS_readlinkat) {
        const char *path = (const char*)a2;
        if (is_hidden(path)) { errno = ENOENT; return -1; }
    }
    if (number == SYS_newfstatat) {
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

bool g_installed = false;

}

void install_hooks(zygisk::Api *api) {
    if (g_installed) return;
    g_installed = true;
    if (!api || !api->pltHookRegister) return;

    if (access("/data/adb/ksu-cloak/debug", F_OK) == 0) g_debug = true;
    LOGI("KSU-Cloak v2 — installing");

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
    api->pltHookRegister(0,0,"dl_iterate_phdr",
        (void*)hook_dl_iterate_phdr,(void**)&orig_dl_iterate_phdr);
    api->pltHookRegister(0,0,"dlopen",(void*)hook_dlopen,(void**)&orig_dlopen);
    api->pltHookRegister(0,0,"dlsym", (void*)hook_dlsym, (void**)&orig_dlsym);

    api->pltHookCommit();
    LOGI("KSU-Cloak v2 — %d hooks committed", 23);
}

}
