CC = gcc
CFLAGS = -no-pie -fno-stack-protector #Make it simpler and less noisy

all: bad_vector good_vector large_vector associativity_test

bad_vector: bad_vector.c
	$(CC) $(CFLAGS) -o bad_vector bad_vector.c

good_vector: good_vector.c
	$(CC) $(CFLAGS) -o good_vector good_vector.c

large_vector: large_vector.c
	$(CC) $(CFLAGS) -o large_vector large_vector.c

associativity_test: associativity_test.c
	$(CC) $(CFLAGS) -o associativity_test associativity_test.c

clean:
	rm -f bad_vector good_vector large_vector associativity_test
