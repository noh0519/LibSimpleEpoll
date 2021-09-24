add_compile_options(-g -Wall -std=c++17)

set(LIBSEPOLL_PATH ../libsepoll/)

add_executable(server main.cpp)

target_include_directories(server
    PUBLIC
    ${LIBSEPOLL_PATH}
)

target_link_directories(server
    PUBLIC
    ${LIBSEPOLL_PATH}/build/
)

target_link_libraries(server
    sepoll
)