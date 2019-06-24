cmake_minimum_required (VERSION 2.6)
project (linkalcs)

include_directories ("./inc")

ADD_DEFINITIONS(-DCOAP_OBSERVE_SERVER_SUPPORTED)
ADD_DEFINITIONS(-DCOAP_OBSERVE_CLIENT_SUPPORTED)

configure_file (
  "./inc/alcs_export.h"
  "${PROJECT_INCLUDE_PATH}/alcs_export.h"
  )
configure_file (
  "./inc/alcs_export_st.h"
  "${PROJECT_INCLUDE_PATH}/alcs_export_st.h"
  )
configure_file (
  "./inc/alcs_export_st_ali.h"
  "${PROJECT_INCLUDE_PATH}/alcs_export_st_ali.h"
  )
configure_file (
  "./inc/alcs_export_dlcp.h"
  "${PROJECT_INCLUDE_PATH}/alcs_export_dlcp.h"
  )
configure_file (
  "./inc/alcs_coap.h"
  "${PROJECT_INCLUDE_PATH}/alcs_coap.h"
  )
configure_file (
  "./inc/alcs_api.h"
  "${PROJECT_INCLUDE_PATH}/alcs_api.h"
  )
configure_file (
  "./inc/alcs_api_internal.h"
  "${PROJECT_INTER_INCLUDE_PATH}/alcs_api_internal.h"
  )

aux_source_directory ("./src" DIR_SRC)
add_library(linkalcs ${DIR_SRC})
target_link_libraries(linkalcs linkcoap linkutils linkplatform)
