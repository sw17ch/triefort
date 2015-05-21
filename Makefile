OPTIMIZE= -O3
WARN=     -Wall -Wextra -pedantic
CFLAGS=   -std=gnu99 ${WARN} ${OPTIMIZE}

TRIEFORT_OBJS=triefort.o sds.o
EXAMPLE_OBJS=example.o ${TRIEFORT_OBJS}
TEST_OBJS=test_triefort.o test_utils.o ${TRIEFORT_OBJS}

ARCHIVE=libtriefort.a

all: example test ${ARCHIVE}

test: ${TEST_OBJS}
	${CC} $^ -o $@

example: ${EXAMPLE_OBJS}
	${CC} -lgcrypt $^ -o $@

${ARCHIVE}: sds.o triefort.o
	ar cr libtriefort.a $^

example.o: example.c triefort.h
sds.o: sds.h sds.c
test_triefort.o: triefort.h triefort_internal_types.h test_triefort.c
test_utils.o: triefort.h test_utils.h test_utils.c
triefort.o: triefort.h triefort_internal_types.h triefort.c

clean:
	rm -f test example *.o ${ARCHIVE}
