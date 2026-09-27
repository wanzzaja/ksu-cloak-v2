```cpp
#pragma once
#include <jni.h>
#include <cstdlib>

#define ZYGISK_API_VERSION 4

namespace zygisk {
struct Api;

struct AppSpecializeArgs {
    jint &uid; jint &gid; jintArray &gids; jint &runtime_flags;
    jobjectArray &rlimits; jint &mount_external; jstring &se_info;
    jstring &nice_name; jstring &instruction_set; jstring &app_data_dir;
    AppSpecializeArgs(jint &u, jint &g, jintArray &gi, jint &rf,
                      jobjectArray &rl, jint &me, jstring &si,
                      jstring &nn, jstring &is, jstring &add)
        : uid(u), gid(g), gids(gi), runtime_flags(rf), rlimits(rl),
          mount_external(me), se_info(si), nice_name(nn),
          instruction_set(is), app_data_dir(add) {}
};

struct ServerSpecializeArgs {
    jint &uid; jint &gid; jintArray &gids; jint &runtime_flags;
    jlong &permitted_capabilities; jlong &effective_capabilities;
    ServerSpecializeArgs(jint &u, jint &g, jintArray &gi, jint &rf, jlong &pc, jlong &ec)
        : uid(u), gid(g), gids(gi), runtime_flags(rf),
          permitted_capabilities(pc), effective_capabilities(ec) {}
};

class ModuleBase {
public:
    ModuleBase() = default;
    virtual ~ModuleBase() = default;
    virtual void onLoad(Api *api, JNIEnv *env) = 0;
    virtual void preAppSpecialize(AppSpecializeArgs *args) = 0;
    virtual void postAppSpecialize(const AppSpecializeArgs *args) = 0;
    virtual void preServerSpecialize(ServerSpecializeArgs *args) = 0;
    virtual void postServerSpecialize(const ServerSpecializeArgs *args) = 0;
};

struct Api {
    int  (*pltHookRegister)(dev_t, ino_t, const char *, void *, void **);
    void (*pltHookCommit)();
    int  (*connectCompanion)(void *);
    void (*setOption)(int);
};
}

#define REGISTER_ZYGISK_MODULE(clazz)                                       \
extern "C" [[gnu::visibility("default")]]                                   \
void zygisk_module_entry(zygisk::Api *api, JNIEnv *env) {                   \
    static clazz module; module.onLoad(api, env); }                         \
extern "C" [[gnu::visibility("default")]] void zygisk_module_ctor() {}      \
extern "C" [[gnu::visibility("default")]] void zygisk_module_dtor() {}
```
