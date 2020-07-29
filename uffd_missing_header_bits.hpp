#include <linux/userfaultfd.h>

// Why isn't this stuff in the 5.7 headers package?
// Until I figure that out, I'm going to throw it in here. I copied this
// from the following kernel commit:
// https://github.com/torvalds/linux/commit/63b2d4174c4ad1f40b48d7138e71bcb564c1fe03

#define _UFFDIO_WRITEPROTECT        (0x06)

#define UFFDIO_WRITEPROTECT     _IOWR(UFFDIO, _UFFDIO_WRITEPROTECT, \
                                      struct uffdio_writeprotect)

struct uffdio_writeprotect {
    struct uffdio_range range;
/*
 * UFFDIO_WRITEPROTECT_MODE_WP: set the flag to write protect a range,
 * unset the flag to undo protection of a range which was previously
 * write protected.
 *
 * UFFDIO_WRITEPROTECT_MODE_DONTWAKE: set the flag to avoid waking up
 * any wait thread after the operation succeeds.
 *
 * NOTE: Write protecting a region (WP=1) is unrelated to page faults,
 * therefore DONTWAKE flag is meaningless with WP=1.  Removing write
 * protection (WP=0) in response to a page fault wakes the faulting
 * task unless DONTWAKE is set.
 */
#define UFFDIO_WRITEPROTECT_MODE_WP		((__u64)1<<0)
#define UFFDIO_WRITEPROTECT_MODE_DONTWAKE	((__u64)1<<1)
    __u64 mode;
};
