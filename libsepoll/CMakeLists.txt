SET(LIBSOURCE AcceptSEpoll.cpp ConnectSEpoll.cpp)

# ADD_LIBRARY(libsepoll STATIC ${LIBSOURCE})
ADD_LIBRARY(libsepoll SHARED ${LIBSOURCE})