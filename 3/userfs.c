#include "userfs.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>

enum {
	BLOCK_SIZE = 512,
	MAX_FILE_SIZE = 1024 * 1024 * 100,
};

/** Global error code. Set from any function on any error. */
static enum ufs_error_code ufs_error_code = UFS_ERR_NO_ERR;

struct block {
	/** Block memory. */
	char *memory;
	/** How many bytes are occupied. */
	int occupied;
	/** Next block in the file. */
	struct block *next;
	/** Previous block in the file. */
	struct block *prev;

	/* PUT HERE OTHER MEMBERS */
};

struct file {
	/** Double-linked list of file blocks. */
	struct block *block_list;
	/**
	 * Last block in the list above for fast access to the end
	 * of file.
	 */
	struct block *last_block;
	/** How many file descriptors are opened on the file. */
	int refs;
	/** File name. */
    char *name;
	/** Files are stored in a double-linked list. */
	struct file *next;
	struct file *prev;

    int deleted;
};

/** List of all files. */
static struct file *file_list = NULL;

struct filedesc {
	struct file *file;
    int block_index;
    int byte_index;

    enum open_flags flags;
    int id;
};

/**
 * An array of file descriptors. When a file descriptor is
 * created, its pointer drops here. When a file descriptor is
 * closed, its place in this array is set to NULL and can be
 * taken by next ufs_open() call.
 */
static struct filedesc **file_descriptors = NULL;
static int file_descriptor_count = 0;
static int file_descriptor_capacity = 0;

enum ufs_error_code
ufs_errno()
{
	return ufs_error_code;
}

/* finding the nearest greater nonzero exponentiation value than the number `n` */
static int
get_upper_sqr(int n) {
    if (n == 0) {
        return 1;
    }

    if ((n & (n - 1)) == 0) {
        return n;
    }

    --n;
    for (int shift = 1; shift < (int)sizeof(n) * 8; shift *= 2) {
        n |= n >> shift;
    }

    return n + 1;
}

static void
add_file_to_list(struct file *f) {
    f->prev = NULL;
    f->next = file_list;

    if (file_list != NULL) {
        file_list->prev = f;
    }

    file_list = f;
}

static void
remove_file_from_list(struct file *f) {
    if (f == NULL) {
        return;
    }

    if (f->prev != NULL) {
        f->prev->next = f->next;
    }

    if (f->next != NULL) {
        f->next->prev = f->prev;
    }

    if (file_list == f) {
        file_list = f->next;
    }

    f->prev = f->next = NULL;
}

static struct file *
create_file(const char *filename) {
    if (filename == NULL) {
        return NULL;
    }

    struct file *f = malloc(sizeof(*f));

    size_t length = strlen(filename);
    f->name = malloc(length + 1);
    f->name[length] = '\0';
    strcpy(f->name, filename);

    f->block_list = f->last_block = NULL;
    f->prev = f->next = NULL;
    f->refs = f->deleted = 0;

    return f;
}

static void
delete_file(struct file **fp) {
    if (fp == NULL || *fp == NULL) {
        return;
    }

    struct file *f = *fp;

    remove_file_from_list(f);

    for (
        struct block *b = f->block_list;
        b != NULL;
    ) {
        struct block *next = b->next;
        free(b->memory);
        free(b);
        b = next;

    }

    if (f->name != NULL) {
        free(f->name);
    }

    free(f);
    *fp = NULL;
}

static int
create_descriptor(struct file *f, enum open_flags flags) {
    if (f == NULL) {
        return -1;
    }

    if (file_descriptor_count == file_descriptor_capacity) {
        file_descriptor_capacity = get_upper_sqr(file_descriptor_capacity * 2);
        file_descriptors = realloc(file_descriptors, file_descriptor_capacity * sizeof(void *));
    }

    /* Attempt to reuse deleted descriptors */
    int fd;
    for (fd = 0; fd < file_descriptor_capacity; ++fd) {
        if (file_descriptors[fd] == NULL) {
            break;
        }
    }

    file_descriptors[fd] = malloc(sizeof(struct filedesc));
    ++file_descriptor_count;

    file_descriptors[fd]->id = fd;
    file_descriptors[fd]->flags = flags;
    file_descriptors[fd]->file = f;
    file_descriptors[fd]->block_index = 0;
    file_descriptors[fd]->byte_index = 0;

    ++f->refs;

    return fd;
}

static int
delete_descriptor(int fd) {
    if (
        fd < 0 || fd >= file_descriptor_capacity ||
        file_descriptor_count == 0 || file_descriptors == NULL
    ) {
        return -1;
    }

    struct file *f = file_descriptors[fd]->file;

    free(file_descriptors[fd]);
    file_descriptors[fd] = NULL;

    --file_descriptor_count;
    if (f != NULL && (--f->refs == 0 && f->deleted == 1)) {
        delete_file(&f);
    }

    return 0;
}

int
ufs_open(const char *filename, int flags)
{
    struct file *f = NULL;
    for (f = file_list; f != NULL; f = f->next) {
        if (strcmp(f->name, filename) == 0) {
            break;
        }
    }

    if (f == NULL && flags == UFS_CREATE) {
        f = create_file(filename);
        add_file_to_list(f);
    }

    if (f == NULL) {
        ufs_error_code = UFS_ERR_NO_FILE;
        return -1;
    }

    return create_descriptor(f, flags);
}

static int
get_occupied_memory(const struct file *f, int block, int byte) {
    if (f == NULL) {
        return -1;
    }

    int occupied = 0;
    int current_block = 0;

    for (
        struct block *b = f->block_list;
        b != NULL && current_block <= block;
        b = b->next, ++current_block
    ) {
        if (current_block == block) {
            occupied += byte;
        } else {
            occupied += b->occupied;
        }
    }

    return occupied;
}

/*
static void
test_write(int fd) {
    struct file *f = file_descriptors[fd]->file;
    int overall_bytes = 0, block_count = 0;
    fprintf(stderr, "All data in file:\n");

    for (struct block *b = f->block_list; b; b = b->next, ++block_count) {
        fprintf(stderr, "\tblock %d: ", block_count);

        for (int i = 0; i < b->occupied; ++i) {
            fprintf(stderr, "%c", b->memory[i]);
        }
        fprintf(stderr, "\n");

        overall_bytes += b->occupied;
    }
    fprintf(stderr, "Overall bytes: %d, overall blocks: %d\n", overall_bytes, block_count);
}
*/

ssize_t
ufs_write(int fd, const char *buf, size_t size)
{
    if (
        fd < 0 || fd >= file_descriptor_capacity ||
        file_descriptor_count == 0 ||
        file_descriptors == NULL ||
        file_descriptors[fd] == NULL ||
        file_descriptors[fd]->file == NULL
    ) {
        ufs_error_code = UFS_ERR_NO_FILE;
        return -1;
    }

    struct filedesc *desc = file_descriptors[fd];

    if (desc->flags == UFS_READ_ONLY) {
        ufs_error_code = UFS_ERR_NO_PERMISSION;
        return -1;
    }

    struct file *f = desc->file;
    if (get_occupied_memory(f, desc->block_index, desc->byte_index) + size > MAX_FILE_SIZE) {
        ufs_error_code = UFS_ERR_NO_MEM;
        return -1;
    }

    ssize_t written_bytes = 0;

    struct block *prev_block = NULL;
    struct block *current_block = f->block_list;

    for (int i = 0; i < desc->block_index; ++i) {
        if (current_block == NULL) {
            desc->block_index = i;
            break;
        }

        prev_block = current_block;
        current_block = current_block->next;
    }

    int block_count = desc->block_index;

    while (written_bytes < (ssize_t)size) {
        if (current_block == NULL) {
            current_block = malloc(sizeof(*current_block));
            current_block->memory = NULL;
            current_block->occupied = 0;
            current_block->next = NULL;

            if (prev_block != NULL) {
                prev_block->next = current_block;
            }

            current_block->prev = prev_block;
        }

        if (f->block_list == NULL) {
            f->block_list = current_block;
        }

        if (current_block->memory == NULL) {
            current_block->memory = malloc(BLOCK_SIZE);
        }

        char *destination_pos = current_block->memory + desc->byte_index;
        const char *source_pos = buf + written_bytes;

        ssize_t block_capacity = BLOCK_SIZE - desc->byte_index;
        if (block_capacity >= (ssize_t)size - written_bytes) {
            block_capacity = size - written_bytes;
        }

        desc->byte_index += block_capacity;

        if (desc->byte_index >= BLOCK_SIZE) {
            desc->block_index += 1;
            desc->byte_index = 0;
            current_block->occupied = BLOCK_SIZE;
        } else if (current_block->occupied < desc->byte_index) {
            current_block->occupied = desc->byte_index;
        }

        memcpy(destination_pos, source_pos, block_capacity);

        written_bytes += block_capacity;
        prev_block = current_block;
        current_block = current_block->next;
        ++block_count;
    }

    return written_bytes;
}

ssize_t
ufs_read(int fd, char *buf, size_t size)
{
    if (
        fd < 0 || fd >= file_descriptor_capacity ||
        file_descriptor_count == 0 ||
        file_descriptors == NULL ||
        file_descriptors[fd] == NULL ||
        file_descriptors[fd]->file == NULL
    ) {
        ufs_error_code = UFS_ERR_NO_FILE;
        return -1;
    }

    struct filedesc *desc = file_descriptors[fd];

    if (desc->flags == UFS_WRITE_ONLY) {
        ufs_error_code = UFS_ERR_NO_PERMISSION;
        return -1;
    }

    if (buf == NULL || size == 0) {
        return 0;
    }

    struct file *f = desc->file;
    struct block *current_block = f->block_list;

    for (int i = 0; i < desc->block_index; ++i) {
        if (current_block == NULL) {
            desc->block_index = i;
            break;
        }

        current_block = current_block->next;
    }

    ssize_t read_bytes = 0;
    while (
        read_bytes < (ssize_t)size &&
        current_block != NULL &&
        current_block->memory != NULL &&
        current_block->occupied > desc->byte_index
    ) {
        char *destination_pos = buf + read_bytes;
        const char *source_pos = current_block->memory + desc->byte_index;

        ssize_t block_capacity = current_block->occupied - desc->byte_index;
        if (block_capacity > (ssize_t)size - read_bytes) {
            block_capacity = size - read_bytes;
        }

        desc->byte_index += block_capacity;
        if (desc->byte_index >= BLOCK_SIZE) {
            desc->block_index += 1;
            desc->byte_index = 0;
        }

        memcpy(destination_pos, source_pos, block_capacity);

        read_bytes += block_capacity;
        current_block = current_block->next;
    }

    return read_bytes;
}

int
ufs_close(int fd)
{
    int code = 0;

    if (delete_descriptor(fd) == -1) {
        ufs_error_code = UFS_ERR_NO_FILE;
        code = -1;
    }

    /*
    if (file_descriptor_count == 0) {
        free(file_descriptors);
        file_descriptors = NULL;
        file_descriptor_capacity = 0;
    }
    */

    return code;
}

int
ufs_delete(const char *filename)
{
    struct file *f = NULL;
    for (f = file_list; f != NULL; f = f->next) {
        if (strcmp(f->name, filename) == 0) {
            break;
        }
    }

    if (f == NULL) {
        ufs_error_code = UFS_ERR_NO_FILE;
        return -1;
    }

    remove_file_from_list(f);
    if (f->refs == 0) {
        delete_file(&f);
    } else {
        f->deleted = 1;
    }

    return 0;
}

#if NEED_RESIZE

int
ufs_resize(int fd, size_t new_size)
{
	/* IMPLEMENT THIS FUNCTION */
	(void)fd;
	(void)new_size;
	ufs_error_code = UFS_ERR_NOT_IMPLEMENTED;
	return -1;
}

#endif

void
ufs_destroy(void)
{
}
