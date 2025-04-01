CFLAGS = -O2 -Wall -Werror
CC=gcc
LIBS   = -lm -lnsl -lsocket
LIBS   = -lm

SRC=udpping.c misc.c hist.c connectsock.c netutils.c
OBJ=${SRC:.c=.o}

udpping: ${OBJ}
	${CC} ${CFLAGS} -o udpping ${OBJ} ${LIBS}

clean:
	rm -f udpping ${OBJ} core

install: udpping
	cp udpping /home/sdo/bin/arch/udpping
	strip /home/sdo/bin/arch/udpping


hist.o: hist.c udpping.h 
misc.o: misc.c udpping.h 
udpping.o: udpping.c udpping.h 
connectsock.o: connectsock.c udpping.h 
