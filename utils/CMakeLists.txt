cmake_minimum_required (VERSION 2.6)
project (linkutils)

configure_file (
  "./digest/utils_md5.h"
  "${PROJECT_INTER_INCLUDE_PATH}/utils_md5.h"
  )
configure_file (
  "./digest/utils_base64.h"
  "${PROJECT_INTER_INCLUDE_PATH}/utils_base64.h"
  )
configure_file (
  "./digest/utils_hmac.h"
  "${PROJECT_INTER_INCLUDE_PATH}/utils_hmac.h"
  )
configure_file (
  "./json/json_parser.h"
  "${PROJECT_INTER_INCLUDE_PATH}/json_parser.h"
  )
configure_file (
  "./lite-list.h"
  "${PROJECT_INTER_INCLUDE_PATH}/lite-list.h"
  )

aux_source_directory ("./digest" DIR_SRC)
aux_source_directory ("./json" DIR_SRC)
add_library(linkutils ${DIR_SRC})

