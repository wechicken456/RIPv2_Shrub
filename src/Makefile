CXX=g++
CC=gcc
CPPFLAGS=-Wall -Werror -O2

SOCKET_TIME_TARGET=socket_time
SOCKET_TIME_SRC=$(SOCKET_TIME_TARGET).c
SOCKET_TIME_OBJ=$(SOCKET_TIME_TARGET).o

TARGET=twig
SRCS=${wildcard *.cc}
MAIN_SRCS=$(filter-out $(SOCKET_TIME_SRC), $(SRCS)) 
MAIN_OBJECTS=${MAIN_SRCS:.cc=.o} # compile all .cc except socket_time.c
HEADERS=${wildcard *.h}

all: $(TARGET) $(SOCKET_TIME) create_symlink

create_symlink: $(TARGET) $(SOCKET_TIME_TARGET)
	ln -fs $(shell pwd)/$(TARGET) ../$(TARGET) 
	ln -fs $(shell pwd)/$(SOCKET_TIME_TARGET) ../$(SOCKET_TIME_TARGET)

# Link main program (all .c except socket_time.c)
$(TARGET): $(MAIN_OBJECTS) 
	$(CXX) $(CPPFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

# Link socket_time separately
$(SOCKET_TIME_TARGET): $(SOCKET_TIME_OBJ)
	$(CC) $(SOCKET_TIME_OBJ) -o $(SOCKET_TIME_TARGET)

$(MAIN_OBJECTS): $(HEADERS)

clean:
	rm -f $(TARGET) *.o *.dmp.myoutput *.dmp.correct
	rm ../$(TARGET) ../$(SOCKET_TIME_TARGET)
