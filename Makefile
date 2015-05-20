PROJECT=  triefort
OPTIMIZE= -O3
WARN=     -Wall -Wextra -pedantic
INCLUDES= -Ivendor/greatest

CFLAGS=   -g -std=gnu99 ${WARN} ${OPTIMIZE} ${INCLUDES}

all: test_${PROJECT}

OBJS=triefort.o

test_${PROJECT}: test_triefort.c ${OBJS}


triefort.o: triefort.h triefort_internal_types.h sds.o
test_utils.o: triefort.h test_utils.h
sds.o: sds.h sds.c

test_${PROJECT}: triefort.o test_utils.o

clean:
	rm -f test_${PROJECT} *.o
