#
# CMake file
#
cmake_minimum_required (VERSION 2.6)
project (browser_driver)
add_executable(browser_driver src/main.c src/browser_driver.c src/browser_driver.h
                         lib/cJSON.c lib/mqttclient.c lib/mqttparser.c
                        lib/cJSON.h lib/mqttclient.h lib/mqttparser.h lib/timing.h)
include_directories(${browser_driver_SOURCE_DIR}/lib)
set_property(TARGET browser_driver PROPERTY C_STANDARD 99)
if (UNIX)
	target_link_libraries (browser_driver m )
endif()
if (WIN32)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_CRT_SECURE_NO_WARNINGS")
	target_link_libraries (browser_driver ws2_32)
endif(WIN32)
