cmake_minimum_required (VERSION 2.6)
project (linkcoap)
configure_file (
  "./CoAPExport.h"
  "${PROJECT_INTER_INCLUDE_PATH}/CoAPExport.h"
  )
configure_file (
  "./CoAPPlatform.h"
  "${PROJECT_INTER_INCLUDE_PATH}/CoAPPlatform.h"
  )
configure_file (
  "./CoAPObserve.h"
  "${PROJECT_INTER_INCLUDE_PATH}/CoAPObserve.h"
  )
configure_file (
  "./CoAPMessage.h"
  "${PROJECT_INTER_INCLUDE_PATH}/CoAPMessage.h"
  )
configure_file (
  "./CoAPResource.h"
  "${PROJECT_INTER_INCLUDE_PATH}/CoAPResource.h"
  )

ADD_DEFINITIONS(-DCOAP_OBSERVE_SERVER_SUPPORTED)
ADD_DEFINITIONS(-DCOAP_OBSERVE_CLIENT_SUPPORTED)

aux_source_directory ("." DIR_SRC)

add_library(linkcoap ${DIR_SRC})
