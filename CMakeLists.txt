# 设置 CMake 的最低要求版本
cmake_minimum_required(VERSION 3.0)

# 设置项目名称
project(vdhcpd)

string(TOLOWER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE_LC)
string(TOUPPER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE_UP)

if (${CMAKE_BUILD_TYPE_LC} MATCHES "release")
  add_compile_options(-O3 -fstack-protector -fno-common)
  add_compile_definitions(_FORTIFY_SOURCE=2)
elseif (${CMAKE_BUILD_TYPE_LC} MATCHES "debug")
  message(STATUS "-- Build Debug")
  add_compile_options(-g -O0 -fstack-protector -fno-common)
  add_compile_definitions(CLIB_DEBUG)
elseif (${CMAKE_BUILD_TYPE_LC} MATCHES "coverity")
  add_compile_options(-g -O0)
  add_compile_definitions(__COVERITY__)
elseif (${CMAKE_BUILD_TYPE_LC} MATCHES "gcov")
  add_compile_options(-g -O0 -fprofile-arcs -ftest-coverage)
  add_compile_definitions(CLIB_DEBUG CLIB_GCOV)
  link_libraries(gcov)
endif()


option(ENABLE_SANITIZE_ADDR "Enable Address Sanitizer" OFF)
set(SANITIZE_ADDR_OPTIONS
    "unmap_shaw_on_exit=1:disable_coredump=0:abort_on_error=1:detect_leaks=0"
    CACHE 
    STRING "Address sanitizer arguments"
)

if (ENABLE_SANITIZE_ADDR)
    message(STATUS "Enable Address Sanitizer")
    add_compile_options(-fsanitize=address)
    add_link_options(-fsanitize=address)
endif()

# # 设置编译选项
# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu11 -Wno-unused ")
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ")
# set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ")

# 设置可执行文件的名称
#set(TARGET vdhcp)

# 设置可执行文件的输出目录
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# 添加宏定义
add_definitions(-D_GNU_SOURCE)
# add_definitions(-DVERSION_VNAAS)

# add_definitions(-DCHECK_PERFORMANCE)

# 添加项目的头文件目录
include_directories(src)

# 添加源文件
set(SOURCES
    src/public/receive.c 
    src/public/receive_bucket.c 
    src/public/xthread.c 
    src/share/array/queue.c 
    src/share/array/trashqueue.c 
    src/share/bitmap/bitmap.c 
    src/share/cjson/cjson.c 
    src/share/inifile/inifile.c 
    src/share/mysql/mydbop.c 
    src/share/mysql/mysqldb.c 
    src/share/rbtree/key_elem.c 
    src/share/rbtree/rbtree.c 
    src/share/rbtree/set_elem.c 
    src/share/rbtree/tag_elem.c 
    src/share/hash.c 
    src/share/magic.c 
    src/share/md5.c 
    src/share/misc.c 
    src/share/windivert.c 
    src/share/xlog.c 
    src/dhcpd/acl.c 
    src/dhcpd/api.c 
    src/dhcpd/dhcpd.c 
    src/dhcpd/dhcpstats.c 
    src/dhcpd/dhcpv4.c 
    src/dhcpd/dhcpv4relay.c 
    src/dhcpd/dhcpv6.c 
    src/dhcpd/dhcpv6relay.c 
    src/dhcpd/local.c 
    src/dhcpd/realtime.c 
    src/dhcpd/server.c 
    src/dhcpd/staticlease.c 
    src/dhcpd/webaction.c 
    src/main.c
)

# 添加头文件
set(HEADERS
    src/public/rbtree_common.h 
    src/public/receive.h 
    src/public/receive_bucket.h 
    src/public/xthread.h 
    src/share/array/queue.h 
    src/share/array/trashqueue.h 
    src/share/bitmap/bitmap.h 
    src/share/bitmap/bitmap_exactvlan.h 
    src/share/bitmap/bitmap_vlan.h 
    src/share/cjson/cjson.h 
    src/share/inifile/inifile.h 
    src/share/list/listdemo.h 
    src/share/mysql/mydbop.h 
    src/share/mysql/mysqldb.h 
    src/share/rbtree/compiler.h 
    src/share/rbtree/key_elem.h 
    src/share/rbtree/rbtree.h 
    src/share/rbtree/rbtree_augmented.h 
    src/share/rbtree/set_elem.h 
    src/share/rbtree/tag_elem.h 
    src/share/defines.h 
    src/share/hash.h 
    src/share/magic.h 
    src/share/md5.h 
    src/share/misc.h 
    src/share/windivert.h 
    src/share/types.h 
    src/share/xlog.h 
    src/dhcpd/acl.h 
    src/dhcpd/api.h 
    src/dhcpd/config.h 
    src/dhcpd/db.h 
    src/dhcpd/dhcpd.h 
    src/dhcpd/dhcppacket.h 
    src/dhcpd/dhcpstats.h 
    src/dhcpd/dhcpv4.h 
    src/dhcpd/dhcpv6.h 
    src/dhcpd/ipcshare.h 
    src/dhcpd/realtime.h 
    src/dhcpd/server.h 
    src/dhcpd/staticlease.h
)

# 设置可执行文件
add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS} )

# 添加链接库和路径（根据不同的架构）
#if (CMAKE_SYSTEM_PROCESSOR  MATCHES   "x86_64")
    message("x86_64")
    target_link_libraries(${PROJECT_NAME} -lpthread -lresolv )
    
    #mysql
    include_directories(/usr/include/mysql) #include
    link_directories(/usr/lib64/mysql)  # -L
    target_link_libraries(${PROJECT_NAME} -lmysqlclient -g) # -l
    
    #zlib
    target_link_libraries(${PROJECT_NAME} -lz)
# elseif (CMAKE_SYSTEM_PROCESSOR  MATCHES  "arm64")
#     message("aarch64")
#     target_link_libraries(${PROJECT_NAME} -ldl -lpthread -lzstd -lresolv)
    
#     link_directories(-L/opt/aarch64-linux/toolchain/11.3.1/aarch64-linux-gnu/jemalloc/lib64)
#     target_link_libraries(${PROJECT_NAME} -ljemalloc) 

#     #mysql
#     include_directories(/opt/aarch64-linux/toolchain/11.3.1/aarch64-linux-gnu/mysql/include) #include
#     link_directories(-L/opt/aarch64-linux/toolchain/11.3.1/aarch64-linux-gnu/mysql/lib)  # -L
#     target_link_libraries(${PROJECT_NAME} -lmysqlclient -g) # -l

#     #zlib
#     include_directories(/opt/aarch64-linux/toolchain/11.3.1/aarch64-linux-gnu/zlib/include) #include
#     link_directories(-L/opt/aarch64-linux/toolchain/11.3.1/aarch64-linux-gnu/zlib/lib)  # -L
#     target_link_libraries(${PROJECT_NAME} -lz) # -l

#     #openssl

#     include_directories(/opt/aarch64-linux/toolchain/11.3.1/aarch64-linux-gnu/openssl/include) #include
#     link_directories(-L /opt/aarch64-linux/toolchain/11.3.1/aarch64-linux-gnu/openssl/lib)  # -L
#     target_link_libraries(${PROJECT_NAME}  -lssl -lcrypt -lcrypto) # -l
 
# endif()

target_link_libraries(${PROJECT_NAME} m)
install(TARGETS ${PROJECT_NAME}
DESTINATION /vrouter/)