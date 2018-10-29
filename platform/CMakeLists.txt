cmake_minimum_required (VERSION 2.6)
project (linkplatform)

include_directories (".")

configure_file (
  "./iot_import.h"
  "${PROJECT_INCLUDE_PATH}/iot_import.h"
  )
configure_file (
  "./iot_import_config.h"
  "${PROJECT_INCLUDE_PATH}/iot_import_config.h"
  )
configure_file (
  "./iot_import_aes.h"
  "${PROJECT_INCLUDE_PATH}/iot_import_aes.h"
  )

IF (CMAKE_SYSTEM_NAME MATCHES "Linux")
    aux_source_directory ("./os/ubuntu" DIR_SRC)
ELSEIF (CMAKE_SYSTEM_NAME MATCHES "Darwin")
    aux_source_directory ("./os/darwin" DIR_SRC)
ELSEIF (CMAKE_SYSTEM_NAME MATCHES "Windows")
    aux_source_directory ("./os/win7" DIR_SRC)
ENDIF (CMAKE_SYSTEM_NAME MATCHES "Linux")

add_library(linkplatform ${DIR_SRC})
