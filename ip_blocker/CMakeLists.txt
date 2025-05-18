cmake_minimum_required(VERSION 3.28)
project(ip_blocker C)

add_library(ip_blocker SHARED
        src/ip_blocker.c
)

set_target_properties(ip_blocker PROPERTIES
        OUTPUT_NAME "_ip_blocker"
)
target_include_directories(ip_blocker PUBLIC
        /usr/local/include/voodoo
)