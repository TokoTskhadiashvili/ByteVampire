cmake_minimum_required(VERSION 3.16)
project(ByteVampire)

set(CMAKE_CXX_STANDARD 17)

add_executable(ByteVampire
    src/main.cpp
    src/core/scanner.cpp
    src/core/network.cpp
    src/templates/loader.cpp
    src/exploit/exploit_engine.cpp
    src/ai/neural_network.cpp
)

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -static-libstdc++")

target_link_libraries(ByteVampire PRIVATE
    -Wl,-Bstatic ssl crypto -Wl,-Bdynamic
    pthread
    dl
)

set_target_properties(ByteVampire PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/dst
)