CXX=gcc
CC=gcc
CPPFLAGS=-Wall -Werror -O2

SOCKET_TIME=socket_time
SOCKET_TIME_SRC=$(SOCKET_TIME).c
SOCKET_TIME_OBJ=$(SOCKET_TIME).o

TARGET=twig
SRCS=${wildcard *.c}
MAIN_SRCS=$(filter-out $(SOCKET_TIME_SRC), $(SRCS)) 
MAIN_OBJECTS=${MAIN_SRCS:.c=.o} # compile all .c except socket_time.c
HEADERS=${wildcard *.h}


all: $(TARGET) $(SOCKET_TIME)

# Link main program (all .c except socket_time.c)
$(TARGET): $(MAIN_OBJECTS) 
	$(CXX) $(CPPFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

# Link socket_time separately
$(SOCKET_TIME_TARGET): $(SOCKET_TIME_OBJ)
	$(CC) $(SOCKET_TIME_OBJ) -o $(SOCKET_TIME_TARGET)

$(MAIN_OBJECTS): $(HEADERS)

clean:
	rm -f $(TARGET) *.o *.dmp.myoutput *.dmp.correct
