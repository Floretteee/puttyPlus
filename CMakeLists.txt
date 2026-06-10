cmake_minimum_required(VERSION 3.7...3.28)
project(puttyPlus LANGUAGES C)

set(CMAKE_C_STANDARD 99)

include(cmake/setup.cmake)

add_subdirectory(doc)

add_compile_definitions(HAVE_CMAKE_H)

include_directories(terminal)

add_library(utils STATIC
  ${GENERATED_COMMIT_C})
add_dependencies(utils cmake_commit_c)
add_subdirectory(utils)
add_subdirectory(stubs)

add_library(logging OBJECT
  logging.c utils/logeventf.c)

add_library(eventloop STATIC
  callback.c timing.c)

add_library(console STATIC
  clicons.c console.c)

add_library(settings STATIC
  cmdline.c settings.c)

add_library(crypto STATIC
  proxy/cproxy.c proxy/sshproxy.c)
add_subdirectory(crypto)

add_library(network STATIC
  errsock.c x11disp.c
  $<TARGET_OBJECTS:logging>
  proxy/proxy.c
  proxy/http.c
  proxy/socks4.c
  proxy/socks5.c
  proxy/telnet.c
  proxy/newmain.c
  proxy/local.c
  proxy/interactor.c)

add_library(keygen STATIC
  import.c)
add_subdirectory(keygen)

add_library(agent STATIC
  sshpubk.c pageant.c aqsync.c)

add_library(guiterminal STATIC
  terminal/terminal.c terminal/bidi.c
  ldisc.c terminal/lineedit.c config.c dialog.c
  $<TARGET_OBJECTS:logging>)

add_library(noterminal STATIC
  stubs/no-term.c ldisc.c)

add_library(all-backends OBJECT
  pinger.c)

add_library(sftpclient STATIC
  psftpcommon.c)
add_subdirectory(ssh)

add_executable(testcrypt
  test/testcrypt.c sshpubk.c ssh/crc-attack-detector.c)
target_link_libraries(testcrypt
  keygen crypto utils ${platform_libraries})

add_executable(test_host_strfoo
  utils/host_strchr_internal.c)
target_compile_definitions(test_host_strfoo PRIVATE TEST)
target_link_libraries(test_host_strfoo utils ${platform_libraries})

add_executable(test_decode_utf8
  utils/decode_utf8.c)
target_compile_definitions(test_decode_utf8 PRIVATE TEST)
target_link_libraries(test_decode_utf8 utils ${platform_libraries})

add_executable(test_unicode_norm
  utils/unicode-norm.c)
target_compile_definitions(test_unicode_norm PRIVATE TEST)
target_link_libraries(test_unicode_norm utils ${platform_libraries})

add_executable(test_tree234
  utils/tree234.c)
target_compile_definitions(test_tree234 PRIVATE TEST)
target_link_libraries(test_tree234 utils ${platform_libraries})

add_executable(test_wildcard
  utils/wildcard.c)
target_compile_definitions(test_wildcard PRIVATE TEST)
target_link_libraries(test_wildcard utils ${platform_libraries})

add_executable(test_cert_expr
  utils/cert-expr.c)
target_compile_definitions(test_cert_expr PRIVATE TEST)
target_link_libraries(test_cert_expr utils ${platform_libraries})

add_executable(bidi_gettype
  terminal/bidi_gettype.c)
target_link_libraries(bidi_gettype guiterminal utils ${platform_libraries})

add_executable(bidi_test
  terminal/bidi_test.c)
target_link_libraries(bidi_test guiterminal utils ${platform_libraries})

# Plink - command-line SSH client
add_executable(plink
  ${platform}/plink.c
  stubs/no-lineedit.c)
be_list(plink Plink SSH)
target_link_libraries(plink
  eventloop noterminal console sshclient settings network crypto
  utils
  ${platform_libraries})
installed_program(plink)

# PuTTYPlus-Term - console SSH client with WebSocket transport
add_executable(puttyplus-term
  ${platform}/puttyplus-term.c
  stubs/no-lineedit.c)
be_list(puttyplus-term PuTTYPlus-Term SSH)
target_link_libraries(puttyplus-term
  noterminal eventloop console sshclient settings network crypto
  utils
  ${platform_libraries})
installed_program(puttyplus-term)

add_executable(pscp
  pscp.c)
be_list(pscp PSCP SSH)
target_link_libraries(pscp
  sftpclient eventloop console sshclient settings network crypto utils
  ${platform_libraries})
installed_program(pscp)

add_executable(psftp
  psftp.c)
be_list(psftp PSFTP SSH)
target_link_libraries(psftp
  sftpclient eventloop console sshclient settings network crypto utils
  ${platform_libraries})
installed_program(psftp)

add_executable(test_conf
  test/test_conf.c
  stubs/no-agent.c
  stubs/no-callback.c
  stubs/no-gss.c
  stubs/no-ldisc.c
  stubs/no-network.c
  stubs/no-timing.c
  proxy/noproxy.c
)
be_list(test_conf TestConf SSH)
target_link_libraries(test_conf sshclient settings network crypto utils ${platform_libraries})

foreach(subdir ${platform} ${extra_dirs})
  add_subdirectory(${subdir})
endforeach()

if(platform STREQUAL unix)
  target_link_libraries(utils charset)
endif()

configure_file(cmake/cmake.h.in ${GENERATED_SOURCES_DIR}/cmake.h)
