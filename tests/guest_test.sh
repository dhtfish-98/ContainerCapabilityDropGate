#!/bin/sh

/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys
/bin/busybox mount -t devtmpfs devtmpfs /dev
/bin/busybox mount -t cgroup2 none /sys/fs/cgroup
printf 'KERNEL_RELEASE='; /bin/busybox uname -r
/usr/bin/runc --version

/usr/bin/runc --root /run/ccdg-runc run --no-pivot \
  --bundle /opt/ccdg/baseline baseline </dev/null
baseline=$?
printf 'BASELINE_EXIT=%d\n' "$baseline"

/usr/bin/runc --root /run/ccdg-runc run --no-pivot \
  --bundle /opt/ccdg/guard guard </dev/null
guard=$?
printf 'GUARD_EXIT=%d\n' "$guard"

/usr/bin/runc --root /run/ccdg-runc run --no-pivot \
  --bundle /opt/ccdg/allow allow </dev/null
allow=$?
printf 'ALLOW_EXIT=%d\n' "$allow"

/usr/bin/runc --root /run/ccdg-runc run --no-pivot --detach \
  --bundle /opt/ccdg/held held </dev/null
held=$?
printf 'HELD_START_EXIT=%d\n' "$held"
if [ "$held" -eq 0 ]; then
  /usr/bin/runc --root /run/ccdg-runc exec --process \
    /opt/ccdg/exec-safe.json held </dev/null
  exec_safe=$?
  printf 'EXEC_SAFE_EXIT=%d\n' "$exec_safe"
  /usr/bin/runc --root /run/ccdg-runc exec --process \
    /opt/ccdg/exec-unsafe-direct.json held </dev/null
  exec_unsafe=$?
  printf 'UNSAFE_DIRECT_EXEC_EXIT=%d\n' "$exec_unsafe"
else
  exec_safe=1
  exec_unsafe=1
fi

if [ "$baseline" -eq 0 ] && [ "$guard" -eq 0 ] && [ "$allow" -eq 0 ] && \
   [ "$held" -eq 0 ] && [ "$exec_safe" -eq 0 ] && [ "$exec_unsafe" -eq 0 ]; then
  printf 'TEST_EXIT=0\n'
else
  printf 'TEST_EXIT=1\n'
fi
/bin/busybox poweroff -f
