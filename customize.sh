#!/system/bin/sh
SKIPUNZIP=0
ui_print "- KSU Cloak v3.0.0 OVERPOWERED"
[ "$ARCH" = "arm64" ] || abort "! hanya arm64"
ui_print "- target: com.shopee.id, com.ss.android.ugc.trill"
set_perm_recursive "$MODPATH/zygisk" 0 0 0755 0644
mkdir -p /data/adb/ksu-cloak
