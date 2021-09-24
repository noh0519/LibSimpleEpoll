add_compile_options(-g -Wall)

set(LIBSEPOLL_PATH ../libsepoll/build/)

add_executable(client main.cpp)

target_include_directories(client
    PUBLIC
    ${LIBSEPOLL_PATH}
)

target_link_directories(client
    PUBLIC
    ${LIBSEPOLL_PATH}
)

target_link_libraries(client
    sepoll
)