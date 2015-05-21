PROJECT=  triefort
OPTIMIZE= -O3
WARN=     -Wall -Wextra -pedantic
INCLUDES= -Ivendor/greatest

CFLAGS=   -g -std=gnu99 ${WARN} ${OPTIMIZE} ${INCLUDES}

all: test_${PROJECT}

OBJS=triefort.o sds.o


triefort.o: triefort.h triefort_internal_types.h
test_utils.o: triefort.h test_utils.h
sds.o: sds.h sds.c

test_${PROJECT}: test_triefort.c test_utils.o ${OBJS}

clean:
	rm -f test_${PROJECT} *.o
