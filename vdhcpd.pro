TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt
CONFIG += object_parallel_to_source
QMAKE_CFLAGS += -std=gnu11
QMAKE_CFLAGS += -Wno-unused

#TARGET = xsdhcp
DESTDIR = ./bin

DEFINES += _GNU_SOURCE
#开启宏表示新架构
#DEFINES += VERSION_VNAAS

INCLUDEPATH += src

#x86_64
contains (QT_ARCH, x86_64) {
message("x86_64")

LIBS += -lpthread -lresolv
LIBS += -ljemalloc

#mysql
INCLUDEPATH += /usr/include/mysql
LIBS += -L/usr/lib64/mysql -lmysqlclient -g

#zlib
LIBS += -lz
}

#AARCH64
contains (QT_ARCH, arm64) {
message("aarch64")
CONFIG (debug, debug|release) {
target.path=/tmp/router/debug
}

CONFIG (release, debug|release) {
target.path=/tmp/router/release
}

LIBS += -ldl -lpthread -lzstd -lresolv
LIBS += -L/opt/aarch64-linux/toolchain/11.3.1/aarch64-linux-gnu/jemalloc/lib64 -ljemalloc

#mysql
INCLUDEPATH += /opt/aarch64-linux/toolchain/11.3.1/aarch64-linux-gnu/mysql/include
LIBS += -L/opt/aarch64-linux/toolchain/11.3.1/aarch64-linux-gnu/mysql/lib -lmysqlclient -g

#zlib
INCLUDEPATH += /opt/aarch64-linux/toolchain/11.3.1/aarch64-linux-gnu/zlib/include
LIBS += -L/opt/aarch64-linux/toolchain/11.3.1/aarch64-linux-gnu/zlib/lib -lz

#openssl
INCLUDEPATH += /opt/aarch64-linux/toolchain/11.3.1/aarch64-linux-gnu/openssl/include
LIBS += -L /opt/aarch64-linux/toolchain/11.3.1/aarch64-linux-gnu/openssl/lib -lssl -lcrypt -lcrypto
}

include(deployment.pri) qtcAddDeployment()

SOURCES += \
    src/public/receive.c \
    src/public/receive_bucket.c \
    src/public/xthread.c \
    src/share/array/queue.c \
    src/share/array/trashqueue.c \
    src/share/bitmap/bitmap.c \
    src/share/cjson/cjson.c \
    src/share/inifile/inifile.c \
    src/share/mysql/mydbop.c \
    src/share/mysql/mysqldb.c \
    src/share/rbtree/key_elem.c \
    src/share/rbtree/rbtree.c \
    src/share/rbtree/set_elem.c \
    src/share/rbtree/tag_elem.c \
    src/share/hash.c \
    src/share/magic.c \
    src/share/md5.c \
    src/share/misc.c \
    src/share/windivert.c \
    src/share/xlog.c \
    src/dhcpd/acl.c \
    src/dhcpd/api.c \
    src/dhcpd/dhcpd.c \
    src/dhcpd/dhcpstats.c \
    src/dhcpd/dhcpv4.c \
    src/dhcpd/dhcpv4relay.c \
    src/dhcpd/dhcpv6.c \
    src/dhcpd/dhcpv6relay.c \
    src/dhcpd/local.c \
    src/dhcpd/realtime.c \
    src/dhcpd/server.c \
    src/dhcpd/staticlease.c \
    src/dhcpd/webaction.c \
    src/main.c

HEADERS += \
    src/public/rbtree_common.h \
    src/public/receive.h \
    src/public/receive_bucket.h \
    src/public/xthread.h \
    src/share/array/queue.h \
    src/share/array/trashqueue.h \
    src/share/bitmap/bitmap.h \
    src/share/bitmap/bitmap_exactvlan.h \
    src/share/bitmap/bitmap_vlan.h \
    src/share/cjson/cjson.h \
    src/share/inifile/inifile.h \
    src/share/list/listdemo.h \
    src/share/mysql/mydbop.h \
    src/share/mysql/mysqldb.h \
    src/share/rbtree/compiler.h \
    src/share/rbtree/key_elem.h \
    src/share/rbtree/rbtree.h \
    src/share/rbtree/rbtree_augmented.h \
    src/share/rbtree/set_elem.h \
    src/share/rbtree/tag_elem.h \
    src/share/defines.h \
    src/share/hash.h \
    src/share/magic.h \
    src/share/md5.h \
    src/share/misc.h \
    src/share/windivert.h \
    src/share/types.h \
    src/share/xlog.h \
    src/dhcpd/acl.h \
    src/dhcpd/api.h \
    src/dhcpd/config.h \
    src/dhcpd/db.h \
    src/dhcpd/dhcpd.h \
    src/dhcpd/dhcppacket.h \
    src/dhcpd/dhcpstats.h \
    src/dhcpd/dhcpv4.h \
    src/dhcpd/dhcpv6.h \
    src/dhcpd/ipcshare.h \
    src/dhcpd/realtime.h \
    src/dhcpd/server.h \
    src/dhcpd/staticlease.h
