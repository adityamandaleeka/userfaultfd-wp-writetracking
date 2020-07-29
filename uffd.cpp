#include <assert.h>
#include <chrono>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <linux/userfaultfd.h>
#include <unistd.h>

// See comment in the header for more info
#include "uffd_missing_header_bits.hpp"

////////////////////////////////////////////////////////////////////
// userfaultfd Write Protection Test
//
// Aditya Mandaleeka
// July 28 2020, Hackathon
//
// This is a sample program I wrote to learn more about the
// userfaultfd write protection capabilities introduced
// recently in the mainline Linux kernel.
//
// In addition to learning, I also wanted to compare how UFFD
// WP compares to using the traditional PROT_NONE+SEGV handler
// trick in order to catch dirtied memory pages. This is useful
// for specific VM/GC usecases; one example is for cross-
// generational write tracking, and another is safepoint polls.
//
// Using signal handlers for such control flow "works", but it
// has problems:
//     - Handling signals is very expensive and involves a lot
//       of work on the kernel side every time a signal is
//       raised. Handling it all in userspace can thus be a
//       performance win.
//     - Modifying access protections on memory regions involves
//       touching the VMA entries in the mm subsystem, which not
//       only involves taking some low-level locks, but also
//       leads to a proliferation of VMAs when dealing with a
//       large address region with permissions that can be dis-
//       contiguous over the span of the process's lifetime.
//       The UFFD code avoids the need to deal with VMAs entirely.
//     - Signal handlers are touchy about what's actually safe
//       to do inside them, so we have to be extra careful when
//       doing interesting things from the context of the SEGV
//       handler, often jumping through extra hoops to make it
//       safe.
//
// Note: all of this was done in an afternoon/evening as part of
// a hackathon, so the code cuts a few corners, but I believe the
// concept is sound and would like to hear if the test can be
// improved!
//
////////////////////////////////////////////////////////////////////

static const int PAGE_SIZE = 4096;
static const int PAGE_COUNT = 5000000;
static const uint64_t ALLOC_SIZE = (uint64_t)PAGE_SIZE * PAGE_COUNT;

// Use a char per page for now. The wasted memory isn't really of interest
// for this experiment;
static char* PAGE_TRACKER;

// Used for tracking the start of the desired region. Think of this like
// a heap base for GC.
// TODO: turn all the dirty tracking stuff into a class and get rid of
// these globals.
static void* REGION_BASE;

// Choose one to use for measuring elapsed time
#define USE_RDTSC 0
#define USE_CHRONO 1
static_assert(USE_CHRONO || USE_RDTSC, "Must specify clock to use for timing!");

// Aren't they?
#define EXTRA_CHECKS_ARE_FUN 0

void* allocate_mem_with_mmap(size_t num_bytes)
{
    void* addr = ::mmap(0,
                  num_bytes,
                  PROT_READ|PROT_WRITE,
                  MAP_PRIVATE|MAP_ANONYMOUS,
                  0 /* fd */,
                  0 /* offset*/);
    if (addr == MAP_FAILED)
    {
        printf("ERROR: mmap failed. errno: %d\n", errno);
        exit(-1);
    }

    return addr;
}

int fill_with_pattern_seq(void* addr, char pattern, uint64_t len_bytes)
{
    char* cur = (char*)addr;
    for (uint64_t i = 0; i < len_bytes; i++)
    {
        *cur = pattern;
        cur++;
    }

    return 0;
}

int n_random_writes(void* addr, char pattern, uint64_t len_bytes, int num_writes)
{
    srand(1337);

    for (int i = 0; i < num_writes; i++)
    {
        int byte_to_set = rand() % len_bytes;
        char* cur = (char*)((uint64_t)addr + byte_to_set);
        *cur = pattern;
        cur++;
    }

    return 0;
}

// Protect a range with UFFD WP
int protect_range(int uffd, void* addr, uint64_t length)
{
    struct uffdio_range range = {
        (__u64)addr,
        length
        };
    struct uffdio_writeprotect wp_args = {range, UFFDIO_WRITEPROTECT_MODE_WP};
    return ioctl(uffd, UFFDIO_WRITEPROTECT, &wp_args);
}

// Protect a range with mprotect
int protect_range_with_mprotect(void* addr, uint64_t length)
{
    int ret = mprotect(addr, length, PROT_NONE);
    if (ret != 0)
    {
        printf("mprotect failed to set PROT_NONE with %d. errno: %d\n", ret, errno);
    }

    return ret;
}

void* align_to_page_boundary(void* addr)
{
    // TODO: make this better
    return (void*)((uint64_t)addr & ~(PAGE_SIZE-1));
}

// Resume without the WP mode
// TODO: Check if there is a canonical way to re-protect it so that any future
// writes to this page are also caught.
int resume_without_wp(int uffd, void* addr, uint64_t length)
{
    addr = align_to_page_boundary(addr);
    struct uffdio_range range = {
        (__u64)addr, 
        length
        };
    struct uffdio_writeprotect wp_args = {range, 0};
    return ioctl(uffd, UFFDIO_WRITEPROTECT, &wp_args);
}

int resume_with_mprotect_rw(void* addr, uint64_t length)
{
    addr = align_to_page_boundary(addr);

    int ret = mprotect(addr, length, PROT_READ|PROT_WRITE);
    if (ret != 0)
    {
        printf("mprotect failed to set RW with %d. errno: %d\n", ret, errno);
    }

    return ret;
}

// Register a range of memory for use with UFFD WP
int register_range_with_wp(int uffd, void* addr, uint64_t length)
{
    struct uffdio_range range = {
        (__u64)addr, 
        length
        };

    unsigned int ctls = 0;
    struct uffdio_register reg_args = {
        range,
        UFFDIO_REGISTER_MODE_WP,
        ctls
    };

    int ret = ioctl(uffd, UFFDIO_REGISTER, &reg_args);

    if (ret != 0)
    {
        printf("UFFDIO_REGISTER failed. errno: %d\n", errno);
        exit(-1);
    }

    return ret;
}

// In a real runtime, this would have to do some extra work to determine whether
// this is a "real" segfault or just the write tracking signal and handle it
// accordingly. We're skipping all that stuff here since we always assume this
// is going to be a write protection fault we caused intentionally.
void sigsegv_handler(int code, siginfo_t *siginfo, void *context)
{
    size_t addr = (size_t)siginfo->si_addr;
    // printf("Yay, SIGSEGV handler caught a write at %p\n", (void*)addr);

    // Dirty the page in our tracker
    int page_number = (addr - (uint64_t)REGION_BASE) / PAGE_SIZE;
    PAGE_TRACKER[page_number] = (char)1;

    resume_with_mprotect_rw((void*)addr, PAGE_SIZE);
}

void register_segv_handler()
{
    struct sigaction action;

    action.sa_flags = SA_RESTART;
    action.sa_handler = NULL;
    action.sa_sigaction = sigsegv_handler;
    action.sa_flags |= SA_SIGINFO;
    sigemptyset(&action.sa_mask);

    int ret = sigaction(SIGSEGV, &action, nullptr);
    if (ret != 0)
    {
        printf("sigaction failed with %d. errno: %d\n", ret, errno);
        exit(-1);
    }
}

#if EXTRA_CHECKS_ARE_FUN
const int SENTINEL_VALUE = 0xBABA;
#endif

// This just holds the things we need to pass to the listener proc
struct uffd_wp_info
{
    int fd;

#if EXTRA_CHECKS_ARE_FUN
    int sentinel;
#endif
};

// TODO: make this better. Using a global for now to make lifetimes simpler.
static struct uffd_wp_info g_wp_info = {0};

void* listener_proc(void* arg)
{
    uffd_wp_info* wp_info = static_cast<uffd_wp_info*>(arg);
    int uffd = wp_info->fd;

#if EXTRA_CHECKS_ARE_FUN
    if (wp_info->sentinel != SENTINEL_VALUE)
    {
        printf("ERROR: Failed sentinel check!\n");
        exit(-1);
    }
#endif

    struct pollfd evt = {
        uffd,
        POLLIN,
        0
        };

    while (poll(&evt, 1, 10) > 0)
    {
        if (evt.revents & (POLLERR | POLLHUP))
        {
            printf("ERROR: Poll Error!\n");
            exit(-1);
        }

        struct uffd_msg fault_msg = {0};
        int ret = read(uffd, &fault_msg, sizeof(fault_msg));
        if (ret != sizeof(fault_msg))
        {
            printf("ERROR: Failed to read a UFFD event! read() returned %d, errno: %d, fd: %d\n", ret, errno, uffd);
        }

        if (fault_msg.event == UFFD_EVENT_PAGEFAULT)
        {
            uint64_t fault_addr = fault_msg.arg.pagefault.address;
            // printf("Yay, UFFD caught a write at %p\n", (void*)fault_addr);

            // Dirty the page in our tracker
            int page_number = (fault_addr - (uint64_t)REGION_BASE) / (uint64_t)PAGE_SIZE;
            PAGE_TRACKER[page_number] = (char)1;

            // Now you send ioctl(uffd, UFFDIO_WRITEPROTECT, struct *uffdio_writeprotect)
            // again while pagefault.mode does not have UFFDIO_WRITEPROTECT_MODE_WP set.
            // This wakes up the thread which will continue to run with writes. This allows
            // you to do the bookkeeping about the write in the uffd reading thread before
            // the ioctl.
            ret = resume_without_wp(uffd, (void*)fault_addr, PAGE_SIZE);
            if (ret != 0)
            {
                printf("Resume failed!: %d\n", ret);
            }
        }
        else
        {
            printf("Unexpected event received: %d\n", fault_msg.event);
        }
    }

    return nullptr;
}

// TODO: proper handling of ret values
int set_up_segv_way(void* buf, uint64_t alloc_size)
{
    register_segv_handler();
    REGION_BASE = buf;
    return protect_range_with_mprotect(buf, alloc_size);
}

// TODO: proper handling of ret values
int set_up_uffd_way(void* buf, uint64_t alloc_size)
{
    REGION_BASE = buf;
    int fd = 0;
    if ((fd = syscall(SYS_userfaultfd, O_NONBLOCK)) == -1)
    {
        printf("ERROR: Initial syscall failed!\n");
        return -1;
    }

    // https://www.kernel.org/doc/Documentation/admin-guide/mm/userfaultfd.rst
    // When first opened the ``userfaultfd`` must be enabled invoking the
    // ``UFFDIO_API`` ioctl specifying a ``uffdio_api.api`` value set to ``UFFD_API`` (or
    // a later API version) which will specify the ``read/POLLIN`` protocol
    // userland intends to speak on the ``UFFD`` and the ``uffdio_api.features``
    // userland requires.
    struct uffdio_api api = { .api = UFFD_API };

    // The ``UFFDIO_API`` ioctl if successful (i.e. if the
    // requested ``uffdio_api.api`` is spoken also by the running kernel and the
    // requested features are going to be enabled) will return into
    // ``uffdio_api.features`` and ``uffdio_api.ioctls`` two 64bit bitmasks of
    // respectively all the available features of the read(2) protocol and
    // the generic ioctl available.
    if (ioctl(fd, UFFDIO_API, &api))
    {
        printf("ERROR: Couldn't get supported UFFD features!\n");
        return -1;
    }

    // The ``uffdio_api.features`` bitmask returned by the ``UFFDIO_API`` ioctl
    // defines what memory types are supported by the ``userfaultfd`` and what
    // events, except page fault notifications, may be generated.
    uint64_t supp_features = api.features;

    // bool supports_missing_shmem = supp_features & UFFD_FEATURE_MISSING_SHMEM;
    // bool supports_hugetlbfs     = supp_features & UFFD_FEATURE_MISSING_HUGETLBFS;
    bool supports_pagefault_wp  = supp_features & UFFD_FEATURE_PAGEFAULT_FLAG_WP;

    if (!supports_pagefault_wp)
    {
        printf("ERROR: Kernel doesn't support WP with UFFD!\n");
        exit(-1);
    }

    int ret = register_range_with_wp(fd, buf, alloc_size);
    ret = protect_range(fd, buf, alloc_size);

    g_wp_info = {
        fd 
#if EXTRA_CHECKS_ARE_FUN
        , SENTINEL_VALUE
#endif
    };

    pthread_t thread = {0};
    if (pthread_create(&thread, NULL, listener_proc, &g_wp_info))
    {
        printf("ERROR: listener thread creation failed!\n");
        exit(-1);
    }

    return ret;
}

uint64_t rdtsc(){
    unsigned int lo,hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}

int initialize_page_tracker()
{
    PAGE_TRACKER = new char[PAGE_COUNT];
    for (int i = 0; i < PAGE_COUNT; i++)
    {
        PAGE_TRACKER[i] = 0;
    }

    return 0;
}

// Putting all the tests in here for now...
class Tests
{
public:
    static bool ensure_writes_succeeded(void* buf)
    {
        for (uint64_t i = 0; i < ALLOC_SIZE; i++)
        {
            char* cur = (char*)buf;
            if (cur[i] != (char)0xAD)
            {
                printf("Sanity test ensure_writes_succeeded failed! Buffer wasn't set correctly!\n");
                printf("i = %llu, value = %d\n", i, cur[i]);
                return false;
            }
        }
        return true;
    }

    static bool ensure_pages_dirtied(uint64_t len)
    {
        for (uint64_t i = 0; i < len; i++)
        {
            if (PAGE_TRACKER[i] != (char)1)
            {
                printf("Sanity test ensure_pages_dirtied failed! Page wasn't dirtied!\n");
                return false;
            }
        }

        return true;
    }

    static uint64_t get_number_of_dirty_pages(uint64_t len)
    {
        uint64_t dirty_count = 0;
        for (uint64_t i = 0; i < len; i++)
        {
            if (PAGE_TRACKER[i] == (char)1)
            {
                dirty_count++;
            }
        }

        return dirty_count;
    }

    static bool perform_full_write_checks(void* buf)
    {
        return ensure_writes_succeeded(buf) && ensure_pages_dirtied(PAGE_COUNT);
    }
};

uint64_t sequential_write_experiment(bool use_uffd)
{
    void* buf = allocate_mem_with_mmap(ALLOC_SIZE);
    initialize_page_tracker();

    fill_with_pattern_seq(buf, 0xEE, ALLOC_SIZE);

    int setup_ret;
    if (use_uffd)
    {
        printf("Performing sequential write experiment with UFFD\n");
        setup_ret = set_up_uffd_way(buf, ALLOC_SIZE);
    }
    else
    {
        printf("Performing sequential write experiment with SEGV\n");
        setup_ret = set_up_segv_way(buf, ALLOC_SIZE);
    }

    if (setup_ret != 0)
    {
        printf("ERROR: setup failed!\n");
        exit(-1);
    }

#if USE_RDTSC
    uint64_t time_start = rdtsc();
#else
    auto time_start = std::chrono::high_resolution_clock::now();
#endif

    // Perform sequential writes in the protected region.
    fill_with_pattern_seq(buf, 0xAD, ALLOC_SIZE);

#if USE_RDTSC
    uint64_t time_end = rdtsc();
    uint64_t elapsed = time_end-time_start;
#else
    auto time_end = std::chrono::high_resolution_clock::now();
    uint64_t elapsed = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start).count();
#endif

    // Make sure it actually did what it was supposed to.
    if (!Tests::perform_full_write_checks(buf))
    {
        printf("ERROR: Sanity checks failed!");
    }

    int ret = ::munmap(buf, ALLOC_SIZE);
    if (ret != 0)
    {
        printf("ERROR: munmap Failed!\n");
    }

    return elapsed;
}

uint64_t random_write_experiment(bool use_uffd, int number_writes, int clean_interval = 0)
{
    void* buf = allocate_mem_with_mmap(ALLOC_SIZE);
    initialize_page_tracker();

    fill_with_pattern_seq(buf, 0xEE, ALLOC_SIZE);

    int setup_ret;
    if (use_uffd)
    {
        printf("Performing random write experiment with UFFD. %d writes. ", number_writes);
        if (clean_interval != 0)
        {
            printf("Reprotecting every %d writes.", clean_interval);
        }
        printf("\n");
        setup_ret = set_up_uffd_way(buf, ALLOC_SIZE);
    }
    else
    {
        printf("Performing random write experiment with SEGV. %d writes. ", number_writes);
        if (clean_interval != 0)
        {
            printf("Reprotecting every %d writes.", clean_interval);
        }
        printf("\n");
        setup_ret = set_up_segv_way(buf, ALLOC_SIZE);
    }

    if (setup_ret != 0)
    {
        printf("SETUP FAILED!\n");
        exit(-1);
    }

#if USE_RDTSC
    uint64_t time_start = rdtsc();
#else
    auto time_start = std::chrono::high_resolution_clock::now();
#endif

    if (clean_interval > 0)
    {
        int remaining_writes = number_writes;
        while (remaining_writes > 0)
        {
            // Perform random writes in the protected region.
            n_random_writes(buf, 0xAD, ALLOC_SIZE, (remaining_writes > clean_interval) ? clean_interval : remaining_writes);
            remaining_writes -= clean_interval;

            if (use_uffd)
            {
                // TODO: This is gross! Get the fd another way.
                protect_range(g_wp_info.fd, buf, ALLOC_SIZE);
            }
            else
            {
                protect_range_with_mprotect(buf, ALLOC_SIZE);
            }
            
        }
    }
    else
    {
        // Perform random writes in the protected region.
        n_random_writes(buf, 0xAD, ALLOC_SIZE, number_writes);
    }

#if USE_RDTSC
    uint64_t time_end = rdtsc();
    uint64_t elapsed = time_end-time_start;
#else
    auto time_end = std::chrono::high_resolution_clock::now();
    uint64_t elapsed = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start).count();
#endif

    int ret = ::munmap(buf, ALLOC_SIZE);
    if (ret != 0)
    {
        printf("ERROR: munmap Failed!\n");
    }

    return elapsed;
}

int main()
{
    printf("Userfaultfd Test Program\n");

    //
    // TEST 1: Sequential writes
    //
    uint64_t elapsed_uffd = sequential_write_experiment(true);
    uint64_t elapsed_segv = sequential_write_experiment(false);
    float pct_delta = (elapsed_uffd - elapsed_segv) / (float)elapsed_segv;

    printf("UFFD ticks elapsed: %" PRIu64 "u\n", elapsed_uffd);
    printf("SEGV ticks elapsed: %" PRIu64 "u\n", elapsed_segv);
    printf("UFFD way was %f%% %s.\n", 100.0 * pct_delta, pct_delta < 0 ? "faster" : "slower");

    //
    // TEST 2: 50000 random writes
    //
    elapsed_uffd = random_write_experiment(true, 50000);
    uint64_t c_dirty_uffd = Tests::get_number_of_dirty_pages(PAGE_COUNT);
    elapsed_segv = random_write_experiment(false, 50000);
    uint64_t c_dirty_segv = Tests::get_number_of_dirty_pages(PAGE_COUNT);
    pct_delta = (elapsed_uffd - elapsed_segv) / (float)elapsed_segv;
    assert(c_dirty_segv && (c_dirty_segv == c_dirty_uffd));

    printf("UFFD ticks elapsed: %" PRIu64 "u\n", elapsed_uffd);
    printf("SEGV ticks elapsed: %" PRIu64 "u\n", elapsed_segv);
    printf("UFFD way was %f%% %s.\n", 100.0 * pct_delta, pct_delta < 0 ? "faster" : "slower");

    //
    // TEST 3: 5000000 random writes, but we reprotect every 10000
    //
    elapsed_uffd = random_write_experiment(true, 5000000, 10000);
    c_dirty_uffd = Tests::get_number_of_dirty_pages(PAGE_COUNT);
    elapsed_segv = random_write_experiment(false, 5000000, 10000);
    c_dirty_segv = Tests::get_number_of_dirty_pages(PAGE_COUNT);
    assert(c_dirty_segv && (c_dirty_segv == c_dirty_uffd));

    pct_delta = (elapsed_uffd - elapsed_segv) / (float)elapsed_segv;

    printf("UFFD ticks elapsed: %" PRIu64 "u\n", elapsed_uffd);
    printf("SEGV ticks elapsed: %" PRIu64 "u\n", elapsed_segv);
    printf("UFFD way was %f%% %s.\n", 100.0 * pct_delta, pct_delta < 0 ? "faster" : "slower");

    printf("All experiments complete.\n");
    return 0;
}
