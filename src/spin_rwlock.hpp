#ifndef SPIN_RWLOCK_HPP
#define SPIN_RWLOCK_HPP

#if defined(__x86_64__) || defined(__i386__)
    #include <xmmintrin.h>
    #define _MM_PAUSE _mm_pause
#else
    #define _MM_PAUSE
#endif // __x86_64__ || __i386__

class spin_lock_read;
class spin_lock_write;

class spin_rwlock {
public:
    spin_rwlock() : m_read_count(0), m_write_count(0), m_is_writing(0) { }

private:
    volatile int m_read_count;
    volatile int m_write_count;
    volatile int m_is_writing;

    friend class spin_lock_read;
    friend class spin_lock_write;
};

class spin_lock_read {
public:
    spin_lock_read(spin_rwlock &lock) : m_lock(lock) {
        int wc = lock.m_write_count;
        int i = 0;
        while (lock.m_write_count > 0) {
            if (wc > lock.m_write_count || i++ > 1000000) // to avoid starvation
                break;
            _MM_PAUSE();
        }

        while (__sync_lock_test_and_set(&lock.m_is_writing, 1)) {
            while (lock.m_is_writing)
                _MM_PAUSE(); // busy-wait
        }
        __sync_fetch_and_add(&lock.m_read_count, 1);
        __sync_lock_release(&m_lock.m_is_writing);
    }

    ~spin_lock_read() {
        unlock();
    }

    void unlock() {
        while (__sync_lock_test_and_set(&m_lock.m_is_writing, 1)) {
            while (m_lock.m_is_writing)
                _MM_PAUSE(); // busy-wait
        }
        __sync_fetch_and_sub(&m_lock.m_read_count, 1);
        __sync_lock_release(&m_lock.m_is_writing);
    }

private:
    spin_rwlock &m_lock;
};

class spin_lock_write {
public:
    spin_lock_write(spin_rwlock &lock) : m_lock(lock) {
        __sync_fetch_and_add(&m_lock.m_write_count, 1);
        for (;;) {
            if (lock.m_read_count > 0)
                continue;

            while (__sync_lock_test_and_set(&lock.m_is_writing, 1)) {
                while (lock.m_is_writing)
                    _MM_PAUSE(); // busy-wait
            }

            if (lock.m_read_count > 0) {
                __sync_lock_release(&m_lock.m_is_writing);
            } else {
                break;
            }
        }
    }

    ~spin_lock_write() {
        unlock();
    }

    void unlock() {
        __sync_lock_release(&m_lock.m_is_writing);
        __sync_fetch_and_sub(&m_lock.m_write_count, 1);
    }

private:
    spin_rwlock &m_lock;
};

#endif // SPIN_RWLOCK_HPP
