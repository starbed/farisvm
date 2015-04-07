#ifndef SPIN_RWLOCK_HPP
#define SPIN_RWLOCK_HPP

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
        while (lock.m_write_count > 0) ;

        while (__sync_lock_test_and_set(&lock.m_is_writing, 1)) {
            while (lock.m_is_writing) ;
            // busy-wait
        }
        __sync_fetch_and_add(&lock.m_read_count, 1);
        __sync_lock_release(&m_lock.m_is_writing);
    }

    ~spin_lock_read() {
        unlock();
    }

    void unlock() {
        while (__sync_lock_test_and_set(&m_lock.m_is_writing, 1)) {
            while (m_lock.m_is_writing) ;
            // busy-wait
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
        for (;;) {
            __sync_fetch_and_add(&m_lock.m_write_count, 1);
            while (__sync_lock_test_and_set(&lock.m_is_writing, 1)) {
                while (lock.m_is_writing) ;
                // busy-wait
            }

            if (lock.m_read_count > 0) {
                unlock();
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
