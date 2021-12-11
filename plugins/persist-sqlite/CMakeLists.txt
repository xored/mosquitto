if(SQLITE3_FOUND)
	set(CLIENT_INC
		"${SQLITE3_INCLUDE_DIRS}"
		"${PTHREAD_INCLUDE_DIR}"
		"${STDBOOL_H_PATH}"
		"${STDINT_H_PATH}"
		"${mosquitto_SOURCE_DIR}"
		"${mosquitto_SOURCE_DIR}/deps"
		"${mosquitto_SOURCE_DIR}/include"
		"${mosquitto_SOURCE_DIR}/src"
	)

	set(CLIENT_DIR "${mosquitto_BINARY_DIR}/lib" "${SQLITE3_DIR}")

	add_library(mosquitto_persist_sqlite MODULE
		clients.c
		client_msgs.c
		init.c
		msg_store.c
		plugin.c
		restore.c
		retains.c
		subscriptions.c
	)

	target_include_directories(mosquitto_persist_sqlite PRIVATE
		${CLIENT_INC} ${SQLITE3_INCLUDE_DIR}
	)
	link_directories(${CLIENT_DIR} "${mosquitto_SOURCE_DIR}")

	set_target_properties(mosquitto_persist_sqlite PROPERTIES
		PREFIX ""
		POSITION_INDEPENDENT_CODE 1
	)

	target_link_libraries(mosquitto_persist_sqlite ${SQLITE3_LIBRARIES})
	if(WIN32)
		target_link_libraries(mosquitto_persist_sqlite mosquitto)
	endif()

	install(TARGETS mosquitto_persist_sqlite
		RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
		LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
	)
endif()
