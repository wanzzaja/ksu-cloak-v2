#!/system/bin/sh
SKIPUNZIP=0
ui_print "- KSU Cloak v5.0.0 FINAL"
[ "$ARCH" = "arm64" ] || abort "! hanya arm64"
ui_print "- Target: Shopee & TikTok (musically)"
set_perm_recursive "$MODPATH/zygisk" 0 0 0755 0644
mkdir -p /data/adb/ksu-cloak
