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


tests: test
test: $(TARGET)
	-chmod a+rx test.x test.[0-9]*
	-./test.11
	-./test.12
	-./test.1
	-./test.2
	-./test.3
	-./test.4
	-./test.5
	-./test.6
	-./test.7
	-./test.8
	-./test.9
	-./test.10

clean:
	rm -f $(TARGET) *.o *.dmp.myoutput *.dmp.correct
