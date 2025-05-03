cmake_minimum_required(VERSION 3.28)
project(yara_rules_scanner C)

add_library(yara_rules_scanner SHARED
        src/yara_rules_scanner.c
)

set_target_properties(yara_rules_scanner PROPERTIES
        OUTPUT_NAME "_yara_rules_scanner"
)

target_link_libraries(yara_rules_scanner
        yara
)

