PROJECT=  triefort
OPTIMIZE= -O3
WARN=     -Wall -Wextra -pedantic
INCLUDES= -Ivendor/greatest

CFLAGS=   -std=c99 ${WARN} ${OPTIMIZE} ${INCLUDES}

all: test_${PROJECT}

OBJS=triefort.o

test_${PROJECT}: test_triefort.c ${OBJS}


triefort.o: triefort.h

test_${PROJECT}: triefort.o

clean:
	rm -f test_${PROJECT} *.o