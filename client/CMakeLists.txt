set(shared_src client_shared.c client_shared.h client_props.c)

if(WITH_SRV)
	add_definitions("-DWITH_SRV")
endif()

set(CLIENT_INC
	"${OPENSSL_INCLUDE_DIR}"
	"${STDBOOL_H_PATH}"
	"${STDINT_H_PATH}"
	"${mosquitto_SOURCE_DIR}"
	"${mosquitto_SOURCE_DIR}/include"
)

set(CLIENT_DIR ${mosquitto_BINARY_DIR}/lib)

if(CJSON_FOUND)
	add_definitions("-DWITH_CJSON")
	set(CLIENT_DIR "${CLIENT_DIR};${CJSON_DIR}")
	set(CLIENT_INC "${CLIENT_INC};${CJSON_INCLUDE_DIRS}")
endif()

if(WITH_WEBSOCKETS AND WITH_WEBSOCKETS_BUILTIN)
	add_definitions("-DWITH_WEBSOCKETS=WS_IS_BUILTIN")
endif()

add_executable(mosquitto_pub pub_client.c pub_shared.c ${shared_src})
add_executable(mosquitto_sub sub_client.c sub_client_output.c ${shared_src})
add_executable(mosquitto_rr rr_client.c pub_shared.c sub_client_output.c ${shared_src})

target_include_directories(mosquitto_pub PRIVATE ${CLIENT_INC})
target_include_directories(mosquitto_sub PRIVATE ${CLIENT_INC})
target_include_directories(mosquitto_rr PRIVATE ${CLIENT_INC})

if (WITH_THREADING AND NOT WIN32)
	set(THREADS_PREFER_PTHREAD_FLAG ON)
	find_package(Threads REQUIRED)

	target_link_libraries(mosquitto_pub PRIVATE Threads::Threads)
	target_link_libraries(mosquitto_sub PRIVATE Threads::Threads)
	target_link_libraries(mosquitto_rr PRIVATE Threads::Threads)
endif()

if(WITH_BUNDLED_DEPS)
	target_include_directories(mosquitto_sub PRIVATE "${mosquitto_SOURCE_DIR}/deps")
	target_include_directories(mosquitto_rr PRIVATE "${mosquitto_SOURCE_DIR}/deps")
endif()

link_directories(${CLIENT_DIR})


if(CJSON_FOUND)
	target_link_libraries(mosquitto_pub PRIVATE ${CJSON_LIBRARIES})
	target_link_libraries(mosquitto_sub PRIVATE ${CJSON_LIBRARIES})
	target_link_libraries(mosquitto_rr PRIVATE ${CJSON_LIBRARIES})
endif()

if(WITH_STATIC_LIBRARIES)
	target_link_libraries(mosquitto_pub PRIVATE libmosquitto_static)
	target_link_libraries(mosquitto_sub PRIVATE libmosquitto_static)
	target_link_libraries(mosquitto_rr PRIVATE libmosquitto_static)
else()
	target_link_libraries(mosquitto_pub PRIVATE libmosquitto)
	target_link_libraries(mosquitto_sub PRIVATE libmosquitto)
	target_link_libraries(mosquitto_rr PRIVATE libmosquitto)
endif()

if(QNX)
	target_link_libraries(mosquitto_pub PRIVATE socket)
	target_link_libraries(mosquitto_sub PRIVATE socket)
	target_link_libraries(mosquitto_rr PRIVATE socket)
endif()

install(TARGETS mosquitto_pub RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(TARGETS mosquitto_sub RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(TARGETS mosquitto_rr RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
