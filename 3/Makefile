GCC_FLAGS = -Wextra -Werror -Wall -Wno-gnu-folding-constant
HEAP_HELP_FLAGS = -ldl -rdynamic

all: test

test:
	gcc $(GCC_FLAGS) userfs.c test.c ../utils/unit.c -I ../utils -o test

heap_help:
	gcc $(GCC_FLAGS) $(HEAP_HELP_FLAGS) userfs.c test.c \
		../utils/unit.c \
		../utils/heap_help/heap_help.c \
		-I ../utils/ \
		-I ../utils/heap_help/ \
		-o test

# For automatic testing systems to be able to just build whatever was submitted
# by a student.
test_glob:
	gcc $(GCC_FLAGS) *.c ../utils/unit.c -I ../utils -o test
