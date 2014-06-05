#ifndef _MUTEX_H_
#define _MUTEX_H_

/*! \file mutex.hpp
 * \brief Mutex definition header.
 * \author Pierre Schweitzer
 *
 * That file contains all the definitions needed to successfully use the mutex.
 * To use the mutex in one application, just include mutex.hpp and build mutex.cpp
 */

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

/**
 * \brief Main mutex class.
 */
class Mutex
{
  private:
#ifdef _WIN32
    /**
     * \internal
     * The mutex lock itself.
     * In case of a Windows build, it is just an handle.
     */
    HANDLE hMutexLock;
#else
    /**
     * \internal
     * The mutex lock itself.
     */
    pthread_mutex_t MutexLock;
#endif

  public:
    /**
     * Mutex constructor.
     *
     * It performs the following operations in the following order:
     *
     * 1a - On Windows build, it creates the mutex. In case of a failure, it throws an exception.
     *
     * 1b - On other platforms, it just initiate the pthread mutex.
     * @return Nothing
     */
    Mutex();
    /**
     * Mutex destructor.
     *
     * It just closes/destroys the mutex.
     * @return Nothing
     */
    ~Mutex();

    /**
     * This function is used to lock the mutex. It will always succeed. But it is blocking as it
     * will wait till the mutex is available.
     * On Windows build, it may throws exceptions under rare conditions.
     * @return Nothing
     */
    void Lock() const;
    /**
     * This function is used to lock the mutex. It performs a simple attempt to lock the mutex.
     * If the mutex couldn't be locked it will return false. This function is not blocking!
     * @return True if the mutex has been locked, false otherwise
     */
    bool TryLock() const;
    /**
     * This function is used to unlock the mutex. It is not blocking.
     * If mutex could not be unlocked (bad caller?) it returns false.
     * @return True if the mutex has been unlocked, false otherwise
     */
    bool Unlock() const;
};
#endif

