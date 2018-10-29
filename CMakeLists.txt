cmake_minimum_required (VERSION 3.2)
MESSAGE(${CMAKE_HOST_SYSTEM_NAME} " - " ${CMAKE_HOST_SYSTEM_VERSION})

#option(ENABLE_TESTING "Build Link-alcs." OFF)

MESSAGE("Project source directory " ${PROJECT_SOURCE_DIR})
set(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/output/lib)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/output/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/output/release/bin)
set(PROJECT_INTER_INCLUDE_PATH "${PROJECT_SOURCE_DIR}/output/include")
set(PROJECT_INCLUDE_PATH "${PROJECT_SOURCE_DIR}/output/include")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g3 -Wall -Werror")

include_directories("${PROJECT_INCLUDE_PATH}")
include_directories("${PROJECT_INTER_INCLUDE_PATH}")

IF (CMAKE_SYSTEM_NAME MATCHES "Linux")
    link_directories ("${PROJECT_SOURCE_DIR}/import/ubuntu/libs" ${LIBRARY_OUTPUT_PATH})
ELSEIF (CMAKE_SYSTEM_NAME MATCHES "Darwin")
    link_directories ("${PROJECT_SOURCE_DIR}/import/darwin/libs" ${LIBRARY_OUTPUT_PATH})
ELSE ()
    link_directories ("${PROJECT_SOURCE_DIR}/import/generic/libs" ${LIBRARY_OUTPUT_PATH})
ENDIF (CMAKE_SYSTEM_NAME MATCHES "Linux")

add_subdirectory(utils)
add_subdirectory(platform)
add_subdirectory(coap)
add_subdirectory(alcs)
add_subdirectory(example)

