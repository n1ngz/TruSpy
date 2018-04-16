make remak
adb push ./armCache.ko /sdcard/
time adb shell insmod /sdcard/armCache.ko testToRun=$1
adb shell rmmod armCache.ko

