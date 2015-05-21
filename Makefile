PROJECT=  triefort
OPTIMIZE= -O3
WARN=     -Wall -Wextra -pedantic
INCLUDES= -Ivendor/greatest
CFLAGS=   -std=gnu99 ${WARN} ${OPTIMIZE} ${INCLUDES}

OBJS=triefort.o sds.o

all: test_${PROJECT}

test_${PROJECT}: test_triefort.c test_utils.o ${OBJS}

triefort.o: triefort.h triefort_internal_types.h
test_utils.o: triefort.h test_utils.h
sds.o: sds.h sds.c

clean:
	rm -f test_${PROJECT} *.o
