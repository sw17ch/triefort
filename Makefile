PROJECT=  triefort
OPTIMIZE= -O3
WARN=     -Wall -Wextra -pedantic
INCLUDES= -Ivendor/greatest

CFLAGS=   -std=c99 ${WARN} ${OPTIMIZE} ${INCLUDES}

all: test_${PROJECT}

OBJS=triefort.o

test_${PROJECT}: test_triefort.c ${OBJS}


triefort.o: triefort.h triefort_internal_types.h
test_utils.o: triefort.h triefort_internal_types.h test_utils.h

test_${PROJECT}: triefort.o test_utils.o

clean:
	rm -f test_${PROJECT} *.o
