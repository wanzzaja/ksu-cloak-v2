#include "zygisk.hpp"
#include "hooks.hpp"
#include <android/log.h>
#include <cstring>

#define LOG_TAG "KSUCloak"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

using namespace zygisk;

namespace {
constexpr const char *kTargetPackages[] = {
    "com.shopee.id",
    "com.ss.android.ugc.trill",
};
bool should_hook(const char *p) {
    if (!p) return false;
    for (const char *t : kTargetPackages) if (strcmp(p, t) == 0) return true;
    return false;
}
}

class KSUCloak : public ModuleBase {
public:
    void onLoad(Api *a, JNIEnv *e) override { api = a; env = e; }
    void preAppSpecialize(AppSpecializeArgs *) override {}
    void postAppSpecialize(const AppSpecializeArgs *args) override {
        if (!env || !args) return;
        const char *pkg = env->GetStringUTFChars(args->nice_name, nullptr);
        if (should_hook(pkg)) {
            LOGI("hooking %s", pkg);
            cloak::install_hooks(api);
        }
        if (pkg) env->ReleaseStringUTFChars(args->nice_name, pkg);
    }
    void preServerSpecialize(ServerSpecializeArgs *) override {}
    void postServerSpecialize(const ServerSpecializeArgs *) override {}
private:
    Api *api = nullptr; JNIEnv *env = nullptr;
};

REGISTER_ZYGISK_MODULE(KSUCloak)
