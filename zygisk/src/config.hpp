#pragma once

namespace cloak {

inline constexpr const char *kHiddenPaths[] = {
    "/data/adb/ksu", "/data/adb/modules", "/data/adb/magisk",
    "/data/adb/ksud", "/data/adb/susfs", "/data/adb/zygisk",
    "/data/adb/lspd", "/data/adb/riru", "/data/adb/ksu-cloak",
    "/debug_ramdisk", "/sbin/su", "/system/bin/su", "/system/xbin/su",
    "/vendor/bin/su", "/sbin/.magisk", "/dev/.magisk", "/dev/.ksu",
    "/dev/susfs", "/dev/.lspd",
};

inline constexpr const char *kHiddenKeywords[] = {
    "magisk", "shamiko", "susfs", "zygisk", "kernelsu",
    "ksud", "lsposed", "riru", "frida", "xposed",
    "substrate", "dobby", "edxposed", "libsu", "ksu-cloak",
};

inline constexpr const char *kSuspiciousThreadNames[] = {
    "zygisk", "lsposed", "lspd", "magisk", "ksud", "riru", "shamiko", "frida", "gum-js-loop", "pool-frida"
};
inline constexpr const char *kSafeThreadName = "RenderThread";

inline constexpr const char *kSuspiciousSockets[] = {
    "lspd", "zygisk", "magisk", "ksu", "shamiko", "frida"
};

inline constexpr const char *kSpoofedProps[][2] = {
    {"ro.boot.verifiedbootstate", "green"},
    {"ro.boot.flash.locked", "1"},
    {"ro.boot.veritymode", "enforcing"},
    {"ro.boot.vbmeta.device_state", "locked"},
    {"ro.boot.warranty_bit", "0"},
    {"ro.warranty_bit", "0"},
    {"ro.boot.secure_hardware", "1"},
    {"ro.debuggable", "0"},
    {"ro.secure", "1"},
    {"ro.adb.secure", "1"},
    {"service.adb.root", "0"},
    {"ro.force.debuggable", "0"},
    {"ro.build.type", "user"},
    {"ro.build.tags", "release-keys"},
    {"ro.build.selinux", "1"},
    {"ro.kernel.qemu", "0"},
    {"ro.hardware", "qcom"},
    {"ro.boot.hardware", "qcom"},
    {"sys.oem_unlock_allowed", "0"},
    {"ro.oem_unlock_supported", "0"},
    {"ro.boot.selinux", "enforcing"},
    {"persist.sys.selinux", "enforcing"},
};

inline constexpr const char *kHiddenProps[] = {
    "ro.kernelsu.version", "ro.magisk.version",
    "persist.magisk.hide", "persist.sys.susfs",
    "init.svc.susfs", "init.svc.kernelsu",
    "ro.lineage.build.version", "ro.modversion",
    "ro.omni.version", "ro.cm.version", "ro.omni.device",
    "ro.lsposed.version", "persist.lsposed.debug",
};

}
