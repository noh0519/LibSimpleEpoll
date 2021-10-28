cmake_minimum_required(VERSION 3.16)

include(FetchContent)

FetchContent_Declare(json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG        v3.9.1
)
FetchContent_Declare(fmt
  GIT_REPOSITORY https://github.com/fmtlib/fmt.git
  GIT_TAG        master
)
FetchContent_Declare(smartdb
  GIT_REPOSITORY https://github.com/chicchicforkfork/SmartDB.git
  GIT_TAG        master
)
# FetchContent_Declare(sensordb
#   GIT_REPOSITORY https://github.com/chicchicforkfork/SensorDB.git
#   GIT_TAG        master
# )
# FetchContent_MakeAvailable(json fmt smartdb sensordb)
FetchContent_MakeAvailable(json fmt smartdb)

add_compile_options(-W -Wall -g -fpermissive -std=c++14)

set(LIBSEPOLL_PATH ../libsepoll/)

add_executable(controller_net main.cpp socketmanager.cpp packet.cpp wlan_provider.cpp pol_collector.cpp md5.cpp sha1.cpp sha1v2.cpp sha256.cpp aria.cpp ap.cpp client.cpp)

target_include_directories(controller_net
PUBLIC
    ${LIBSEPOLL_PATH}
    ${smartdb_INCLUDE_DIRS}
)

target_link_directories(controller_net
PUBLIC
    ${LIBSEPOLL_PATH}/build/
)

target_link_libraries(controller_net
    pthread
    sepoll
    smartdb
    fmt
)