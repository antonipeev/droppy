cmake_minimum_required(VERSION 3.10)
project(droppy C)

set(CMAKE_C_STANDARD 11)

set(SOURCES
        droppy.c
        net.c
        net.h
        server.c
        server.h
        http.h
        http.c
        client.c
        client.h
        files.c
        files.h
)

find_package(MbedTLS CONFIG REQUIRED)

add_executable(droppy ${SOURCES})

target_link_libraries(droppy
        PRIVATE
        MbedTLS::mbedtls
        MbedTLS::mbedx509
        MbedTLS::mbedcrypto
)

if(WIN32)
    target_link_libraries(droppy PRIVATE ws2_32)
else()
    target_link_libraries(droppy PRIVATE pthread)
endif()

install(TARGETS droppy DESTINATION bin)
