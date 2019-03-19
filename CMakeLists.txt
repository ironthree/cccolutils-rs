cmake_minimum_required(
        VERSION 2.6
)

project(
        cccolutils-rs
)

find_package(
        PkgConfig REQUIRED
)

pkg_check_modules(
        KRB5 REQUIRED krb5
)

add_executable(
        cccolutils-test
        src/cccolutils.c
        src/test.c
)

target_link_libraries(
        cccolutils-test
        ${KRB5_LIBRARIES}
)

target_include_directories(
        cccolutils-test
        PRIVATE
        ${KRB5_INCLUDE_DIRS}
)

target_compile_options(
        cccolutils-test
        PRIVATE
        ${KRB5_CFLAGS_OTHER}
)
