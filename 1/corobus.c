#include "corobus.h"

#include "libcoro.h"
#include "rlist.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

struct data_vector {
	unsigned *data;
	size_t size;
	size_t capacity;
};

/** Append @a count messages in @a data to the end of the vector. */
static void
data_vector_append_many(struct data_vector *vector,
	const unsigned *data, size_t count)
{
	if (vector->size + count > vector->capacity) {
		if (vector->capacity == 0)
			vector->capacity = 4;
		else
			vector->capacity *= 2;
		if (vector->capacity < vector->size + count)
			vector->capacity = vector->size + count;
		vector->data = realloc(vector->data,
			sizeof(vector->data[0]) * vector->capacity);
	}
	memcpy(&vector->data[vector->size], data, sizeof(data[0]) * count);
	vector->size += count;
}

/** Append a single message to the vector. */
static void
data_vector_append(struct data_vector *vector, unsigned data)
{
	data_vector_append_many(vector, &data, 1);
}

/** Pop @a count of messages into @a data from the head of the vector. */
static void
data_vector_pop_first_many(struct data_vector *vector, unsigned *data, size_t count)
{
	assert(count <= vector->size);
	memcpy(data, vector->data, sizeof(data[0]) * count);
	vector->size -= count;
	memmove(vector->data, &vector->data[count], vector->size * sizeof(vector->data[0]));
}

/** Pop a single message from the head of the vector. */
static unsigned
data_vector_pop_first(struct data_vector *vector)
{
	unsigned data = 0;
	data_vector_pop_first_many(vector, &data, 1);
	return data;
}

/**
 * One coroutine waiting to be woken up in a list of other
 * suspended coros.
 */
struct wakeup_entry {
	struct rlist base;
	struct coro *coro;
};

/** A queue of suspended coros waiting to be woken up. */
struct wakeup_queue {
	struct rlist coros;
};

/** Suspend the current coroutine until it is woken up. */
static void
wakeup_queue_suspend_this(struct wakeup_queue *queue)
{
	struct wakeup_entry entry;
	entry.coro = coro_this();
	rlist_add_tail_entry(&queue->coros, &entry, base);
	coro_suspend();
	rlist_del_entry(&entry, base);
}

/** Wakeup the first coroutine in the queue. */
static void
wakeup_queue_wakeup_first(struct wakeup_queue *queue)
{
	if (rlist_empty(&queue->coros))
		return;
	struct wakeup_entry *entry = rlist_first_entry(&queue->coros,
		struct wakeup_entry, base);
	coro_wakeup(entry->coro);
}

struct coro_bus_channel {
	/** Channel max capacity. */
	size_t size_limit;
	/** Coroutines waiting until the channel is not full. */
	struct wakeup_queue send_queue;
	/** Coroutines waiting until the channel is not empty. */
	struct wakeup_queue recv_queue;
	/** Message queue. */
	struct data_vector data;
};

struct coro_bus {
	struct coro_bus_channel **channels;
	int channel_count;
};

static enum coro_bus_error_code global_error = CORO_BUS_ERR_NONE;

enum coro_bus_error_code
coro_bus_errno(void)
{
	return global_error;
}

void
coro_bus_errno_set(enum coro_bus_error_code err)
{
	global_error = err;
}

struct coro_bus *
coro_bus_new(void)
{
    struct coro_bus *bus = malloc(sizeof(struct coro_bus));
    if (!bus) {
        return NULL;
    }
    bus->channel_count = 0;
    bus->channels = NULL;

    coro_bus_errno_set(CORO_BUS_ERR_NONE);
    return bus;
}

void
coro_bus_delete(struct coro_bus *bus)
{
    if (!bus) {
        return;
    }

    for (int channel_i = 0; channel_i < bus->channel_count; ++channel_i) {
        if (!bus->channels[channel_i]) {
            continue;
        }
        assert(rlist_empty(&bus->channels[channel_i]->send_queue.coros));
        assert(rlist_empty(&bus->channels[channel_i]->recv_queue.coros));
        free(bus->channels[channel_i]->data.data);
        free(bus->channels[channel_i]);
    }
    free(bus->channels);
    free(bus);

    coro_bus_errno_set(CORO_BUS_ERR_NONE);
}

int
coro_bus_channel_open(struct coro_bus *bus, size_t size_limit)
{
    if (!bus) {
        return -1;
    }

    struct coro_bus_channel *channel = malloc(sizeof(struct coro_bus_channel));
    if (!channel) {
        return -1;
    }
    channel->size_limit = size_limit;
    channel->data.data = NULL;
    channel->data.size = 0;
    channel->data.capacity = 0;
    rlist_create(&channel->send_queue.coros);
    rlist_create(&channel->recv_queue.coros);

    // reuse the first deleted channel
    for (int channel_i = 0; bus->channels && channel_i < bus->channel_count; ++channel_i) {
        if (!bus->channels[channel_i]) {
            bus->channels[channel_i] = channel;
            return channel_i;
        }
    }

    // add new channel to the storage
    struct coro_bus_channel **tmp = realloc(
        bus->channels,
        (bus->channel_count + 1) * sizeof(struct coro_bus_channel *)
    );

    if (!tmp) {
        free(channel);
        coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);
        return -1;
    }

    tmp[bus->channel_count] = channel;
    bus->channels = tmp;

    coro_bus_errno_set(CORO_BUS_ERR_NONE);
    return bus->channel_count++;
}

void
coro_bus_channel_close(struct coro_bus *bus, int channel)
{
    if (
        !bus ||
        !bus->channels || channel < 0 ||
        channel >= bus->channel_count ||
        !bus->channels[channel]
    ) {
        return;
    }

    struct coro_bus_channel *ch = bus->channels[channel];

    while (!rlist_empty(&ch->recv_queue.coros)) {
        coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);
        struct wakeup_entry *entry = rlist_first_entry(
            &ch->recv_queue.coros,
            struct wakeup_entry,
            base
        );
        rlist_del_entry(entry, base);
        coro_wakeup(entry->coro);
    }
    while (!rlist_empty(&ch->send_queue.coros)) {
        coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);
        struct wakeup_entry *entry = rlist_first_entry(
            &ch->send_queue.coros,
            struct wakeup_entry,
            base
        );
        rlist_del_entry(entry, base);
        coro_wakeup(entry->coro);
    }

    free(ch->data.data);
    free(ch);
    bus->channels[channel] = NULL;
}

int
coro_bus_send(struct coro_bus *bus, int channel, unsigned data)
{
	/*
	 * Try sending in a loop, until success. If error, then
	 * check which one is that. If 'wouldblock', then suspend
	 * this coroutine and try again when woken up.
	 *
	 * If see the channel has space, then wakeup the first
	 * coro in the send-queue. That is needed so when there is
	 * enough space for many messages, and many coroutines are
	 * waiting, they would then wake each other up one by one
	 * as lone as there is still space.
	 */

    if (
        !bus ||
        !bus->channels || channel < 0 ||
        channel >= bus->channel_count ||
        !bus->channels[channel]
    ) {
        coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);
        return -1;
    }

    struct coro_bus_channel *ch = bus->channels[channel];
    while (ch->data.size >= ch->size_limit) {
        wakeup_queue_suspend_this(&ch->send_queue);
        if (bus->channels[channel] != ch) {
    	    coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);
            return -1;
        }
    }

    data_vector_append(&ch->data, data);
    wakeup_queue_wakeup_first(&ch->recv_queue);

    return 0;
}

int
coro_bus_try_send(struct coro_bus *bus, int channel, unsigned data)
{
	/*
	 * Append data if has space. Otherwise 'wouldblock' error.
	 * Wakeup the first coro in the recv-queue! To let it know
	 * there is data.
	 */
    if (
        !bus ||
        !bus->channels || channel < 0 ||
        channel >= bus->channel_count ||
        !bus->channels[channel]
    ) {
        coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);
        return -1;
    }

    struct coro_bus_channel *ch = bus->channels[channel];
    if (ch->data.size >= ch->size_limit) {
        coro_bus_errno_set(CORO_BUS_ERR_WOULD_BLOCK);
        return -1;
    }

    data_vector_append(&ch->data, data);
    wakeup_queue_wakeup_first(&ch->recv_queue);

    return 0;
}

int
coro_bus_recv(struct coro_bus *bus, int channel, unsigned *data)
{
    if (
        !bus ||
        !bus->channels || channel < 0 ||
        channel >= bus->channel_count ||
        !bus->channels[channel]
    ) {
        coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);
        return -1;
    }

    struct coro_bus_channel *ch = bus->channels[channel];
    while (ch->data.size == 0) {
        wakeup_queue_suspend_this(&ch->recv_queue);
        if (bus->channels[channel] != ch) {
    	    coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);
            return -1;
        }
    }

    *data = data_vector_pop_first(&ch->data);
    wakeup_queue_wakeup_first(&ch->send_queue);

    return 0;
}

int
coro_bus_try_recv(struct coro_bus *bus, int channel, unsigned *data)
{
    if (
        !bus ||
        !bus->channels || channel < 0 ||
        channel >= bus->channel_count ||
        !bus->channels[channel]
    ) {
        coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);
        return -1;
    }

    struct coro_bus_channel *ch = bus->channels[channel];
    if (ch->data.size == 0) {
        coro_bus_errno_set(CORO_BUS_ERR_WOULD_BLOCK);
        return -1;
    }

    *data = data_vector_pop_first(&ch->data);
    wakeup_queue_wakeup_first(&ch->send_queue);

    return 0;
}


#if NEED_BROADCAST

int
coro_bus_broadcast(struct coro_bus *bus, unsigned data)
{
    if (!bus || !bus->channels || bus->channel_count <= 0) {
        coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);
        return -1;
    }

    int current_channel_count = bus->channel_count;
    bool *channel_existed = malloc(current_channel_count * sizeof(bool));
    memset(channel_existed, 0, current_channel_count * sizeof(bool));
    int existing_channel_count = current_channel_count;

    bool sleeped = false;
    for (int channel_i = 0; channel_i < bus->channel_count; ++channel_i) {
        struct coro_bus_channel *channel = bus->channels[channel_i];

        if (!channel && !channel_existed[channel_i]) {
            --existing_channel_count;
            continue;
        } else if (!channel && channel_existed[channel_i]) { // channel existed, but now is missing
            free(channel_existed);
            coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);
            return -1;
        }

        /*
         * even if channel was missing,
         * but after sleeping was created,
         * then coroutine must send the message to it.
         */
        if (!channel_existed[channel_i]) {
            ++existing_channel_count;
        }
        channel_existed[channel_i] = 1; // channel exists

        // check if channel is full and wait until it's release
        while (channel->data.size >= channel->size_limit) {
            wakeup_queue_suspend_this(&channel->send_queue);

            if (
                !bus || !bus->channels ||
                bus->channel_count <= 0
            ) {
                free(channel_existed);
                return 0;
            } else if (!bus->channels[channel_i]) {
                channel_existed[channel_i] = 0; // channel was dropped before the first sleep
            }

            if (current_channel_count != bus->channel_count) {
                bool *tmp = realloc(channel_existed, bus->channel_count * sizeof(bool));
                if (!tmp) {
                    free(channel_existed);
                    return -1;
                }
                channel_existed = tmp;

                // set new channels as potential holes
                if (current_channel_count < bus->channel_count) {
                    memset(
                        channel_existed + current_channel_count,
                        0,
                        (bus->channel_count - current_channel_count) * sizeof(bool)
                    );
                }
                // update channel count
                current_channel_count = bus->channel_count;
            }
            sleeped = true;
        }

        if (sleeped) { // if sleeped, check previous channels once more
            channel_i = -1;
            existing_channel_count = current_channel_count;
            sleeped = false;
        }
    }

    if (!existing_channel_count) {
        free(channel_existed);
        coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);
        return -1;
    }

    // all channels are free, send messages in loop
    for (int channel_i = 0; channel_i < bus->channel_count; ++channel_i) {
        struct coro_bus_channel *channel = bus->channels[channel_i];
        if (!channel && channel_existed[channel_i]) {
            free(channel_existed);
            coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);
            return -1;
        } else if (!channel) {
            continue;
        }

        coro_bus_try_send(bus, channel_i, data);
    }

    free(channel_existed);

    return 0;
}

int
coro_bus_try_broadcast(struct coro_bus *bus, unsigned data) {
    if (!bus || !bus->channels) {
        coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);
        return -1;
    }

    bool *channel_existed = malloc(bus->channel_count * sizeof(bool));
    memset(channel_existed, 0, bus->channel_count * sizeof(bool));
    int existing_channel_count = bus->channel_count;

    for (int channel_i = 0; channel_i < bus->channel_count; ++channel_i) {
        struct coro_bus_channel *channel = bus->channels[channel_i];

        if (!channel) {
            --existing_channel_count;
            continue;
        }
        channel_existed[channel_i] = 1; // channel exists

        if (channel->data.size >= channel->size_limit) {
            free(channel_existed);
            return -1;
        }
    }

    if (!existing_channel_count) {
        free(channel_existed);
        coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);
        return -1;
    }

    for (int channel_i = 0; channel_i < bus->channel_count; ++channel_i) {
        struct coro_bus_channel *channel = bus->channels[channel_i];

        // if channel existed, but now is missing, then return with error
        if (!channel && channel_existed[channel_i]) {
            free(channel_existed);
            coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);
            return -1;
        } else if (!channel) {
            continue; // skip holes
        }

        coro_bus_try_send(bus, channel_i, data);
    }

    free(channel_existed);

    return 0;
}

#endif

#if NEED_BATCH

int
coro_bus_send_v(struct coro_bus *bus, int channel, const unsigned *data, unsigned count)
{
	/* IMPLEMENT THIS FUNCTION */
	(void)bus;
	(void)channel;
	(void)data;
	(void)count;
	coro_bus_errno_set(CORO_BUS_ERR_NOT_IMPLEMENTED);
	return -1;
}

int
coro_bus_try_send_v(struct coro_bus *bus, int channel, const unsigned *data, unsigned count)
{
	/* IMPLEMENT THIS FUNCTION */
	(void)bus;
	(void)channel;
	(void)data;
	(void)count;
	coro_bus_errno_set(CORO_BUS_ERR_NOT_IMPLEMENTED);
	return -1;
}

int
coro_bus_recv_v(struct coro_bus *bus, int channel, unsigned *data, unsigned capacity)
{
	/* IMPLEMENT THIS FUNCTION */
	(void)bus;
	(void)channel;
	(void)data;
	(void)capacity;
	coro_bus_errno_set(CORO_BUS_ERR_NOT_IMPLEMENTED);
	return -1;
}

int
coro_bus_try_recv_v(struct coro_bus *bus, int channel, unsigned *data, unsigned capacity)
{
	/* IMPLEMENT THIS FUNCTION */
	(void)bus;
	(void)channel;
	(void)data;
	(void)capacity;
	coro_bus_errno_set(CORO_BUS_ERR_NOT_IMPLEMENTED);
	return -1;
}

#endif
