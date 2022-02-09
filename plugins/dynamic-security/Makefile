R=../..
include ${R}/config.mk

.PHONY : all binary check clean reallyclean test install uninstall

PLUGIN_NAME=mosquitto_dynamic_security
LOCAL_CPPFLAGS=-I${R}/lib/ -I${R}/src/ -I${R}/plugins/shared -DWITH_CJSON -DWITH_TLS
ifeq ($(WITH_BUNDLED_DEPS),yes)
	LOCAL_CPPFLAGS:=$(LOCAL_CPPFLAGS) -I${R}/deps
endif

OBJS=	\
		acl.o \
		auth.o \
		base64_mosq.o \
		clients.o \
		clientlist.o \
		config.o \
		config_init.o \
		control.o \
		default_acl.o \
		groups.o \
		grouplist.o \
		hash.o \
		json_help.o \
		misc_mosq.o \
		password_mosq.o \
		plugin.o \
		plugin_shared.o \
		roles.o \
		rolelist.o

ifeq ($(WITH_CJSON),yes)
ifeq ($(WITH_TLS),yes)
ALL_DEPS:= binary
else
ALL_DEPS:=
endif
else
ALL_DEPS:=
endif

all : ${ALL_DEPS}
binary : ${PLUGIN_NAME}.so

${PLUGIN_NAME}.so : ${OBJS}
	${CROSS_COMPILE}${CC} $(PLUGIN_LDFLAGS) -fPIC -shared $^ -o $@ -lcjson

acl.o : acl.c dynamic_security.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(PLUGIN_CPPFLAGS) $(PLUGIN_CFLAGS) -c $< -o $@

auth.o : auth.c dynamic_security.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(PLUGIN_CPPFLAGS) $(PLUGIN_CFLAGS) -c $< -o $@

base64_mosq.o : ${R}/lib/base64_mosq.c ${R}/lib/base64_mosq.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(PLUGIN_CPPFLAGS) $(PLUGIN_CFLAGS) -c $< -o $@

clients.o : clients.c dynamic_security.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(PLUGIN_CPPFLAGS) $(PLUGIN_CFLAGS) -c $< -o $@

clientlist.o : clientlist.c dynamic_security.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(PLUGIN_CPPFLAGS) $(PLUGIN_CFLAGS) -c $< -o $@

config.o : config.c dynamic_security.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(PLUGIN_CPPFLAGS) $(PLUGIN_CFLAGS) -c $< -o $@

config_init.o : config_init.c dynamic_security.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(PLUGIN_CPPFLAGS) $(PLUGIN_CFLAGS) -c $< -o $@

control.o : control.c dynamic_security.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(PLUGIN_CPPFLAGS) $(PLUGIN_CFLAGS) -c $< -o $@

default_acl.o : default_acl.c dynamic_security.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(PLUGIN_CPPFLAGS) $(PLUGIN_CFLAGS) -c $< -o $@

groups.o : groups.c dynamic_security.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(PLUGIN_CPPFLAGS) $(PLUGIN_CFLAGS) -c $< -o $@

grouplist.o : grouplist.c dynamic_security.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(PLUGIN_CPPFLAGS) $(PLUGIN_CFLAGS) -c $< -o $@

hash.o : hash.c dynamic_security.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(PLUGIN_CPPFLAGS) $(PLUGIN_CFLAGS) -c $< -o $@

json_help.o : ${R}/plugins/shared/json_help.c ${R}/plugins/shared/json_help.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(PLUGIN_CPPFLAGS) $(PLUGIN_CFLAGS) -c $< -o $@

misc_mosq.o : ${R}/lib/misc_mosq.c dynamic_security.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(PLUGIN_CPPFLAGS) $(PLUGIN_CFLAGS) -c $< -o $@

password_mosq.o : ${R}/src/password_mosq.c dynamic_security.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(PLUGIN_CPPFLAGS) $(PLUGIN_CFLAGS) -c $< -o $@

plugin.o : plugin.c dynamic_security.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(PLUGIN_CPPFLAGS) $(PLUGIN_CFLAGS) -c $< -o $@

plugin_shared.o : ${R}/plugins/shared/plugin_shared.c dynamic_security.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(PLUGIN_CPPFLAGS) $(PLUGIN_CFLAGS) -c $< -o $@

roles.o : roles.c dynamic_security.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(PLUGIN_CPPFLAGS) $(PLUGIN_CFLAGS) -c $< -o $@

rolelist.o : rolelist.c dynamic_security.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(PLUGIN_CPPFLAGS) $(PLUGIN_CFLAGS) -c $< -o $@

reallyclean : clean
clean:
	-rm -f *.o ${PLUGIN_NAME}.so *.gcda *.gcno

check: test
test:

install: all
ifeq ($(WITH_CJSON),yes)
ifeq ($(WITH_TLS),yes)
	$(INSTALL) -d "${DESTDIR}$(libdir)"
	$(INSTALL) ${STRIP_OPTS} ${PLUGIN_NAME}.so "${DESTDIR}${libdir}/${PLUGIN_NAME}.so"
endif
endif

uninstall :
	-rm -f "${DESTDIR}${libdir}/${PLUGIN_NAME}.so"
