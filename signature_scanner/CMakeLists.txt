cmake_minimum_required(VERSION 3.28)
project(signature_scanner C)

find_package(PostgreSQL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(GLIB REQUIRED glib-2.0)

add_library(signature_scanner SHARED
        src/signature_scanner.c
        src/helpers.c
        include/signature_scanner/helpers.h
)

set_target_properties(signature_scanner PROPERTIES
        OUTPUT_NAME "_signature_scanner"
)

target_include_directories(signature_scanner PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        /usr/local/include/voodoo-av
        /usr/local/include/voodoo-av/infrastructure
        /usr/local/include/voodoo-av/domain
        ${PostgreSQL_INCLUDE_DIRS}
        ${GLIB_INCLUDE_DIRS}
)

target_link_libraries(signature_scanner PRIVATE
        ${PostgreSQL_LIBRARIES}
        ${GLIB_LIBRARIES}
)