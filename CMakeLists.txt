cmake_minimum_required(VERSION 3.28)
project(plugins C)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY /usr/lib/voodoo/plugins)

add_subdirectory(signature_scanner)
add_subdirectory(yara_rules_scanner)
add_subdirectory(ip_blocker)
