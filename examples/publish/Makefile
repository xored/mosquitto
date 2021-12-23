include ../../config.mk

.PHONY: all

all : basic-1 basic-websockets-1

basic-1 : basic-1.o
	${CROSS_COMPILE}${CC} $^ -o $@ ../../lib/libmosquitto.so.${SOVERSION}

basic-websockets-1 : basic-websockets-1.o
	${CROSS_COMPILE}${CC} $^ -o $@ ../../lib/libmosquitto.so.${SOVERSION}

basic-1.o : basic-1.c ../../lib/libmosquitto.so.${SOVERSION}
	${CROSS_COMPILE}${CC} -c $< -o $@ -I../../include ${CPPFLAGS} ${CFLAGS}

basic-websockets-1.o : basic-websockets-1.c ../../lib/libmosquitto.so.${SOVERSION}
	${CROSS_COMPILE}${CC} -c $< -o $@ -I../../include ${CPPFLAGS} ${CFLAGS}

../../lib/libmosquitto.so.${SOVERSION} :
	$(MAKE) -C ../../lib

clean :
	-rm -f *.o sub_single sub_multiple
