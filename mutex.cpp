/*! \file mutex.cpp
 * \brief Mutex implementation file.
 * \author Pierre Schweitzer
 *
 * That file contains all the implementations for the mutex.
 * Build it when using mutex. And include header.
 */


#include "mutex.hpp"

Mutex::Mutex()
{
#ifdef _WIN32
  hMutexLock = CreateMutex(NULL, FALSE, NULL);
  if (!hMutexLock)
  {
    throw 0;
  }
#else
  /* Simple init */
  pthread_mutex_init(&MutexLock, 0);
#endif
}

Mutex::~Mutex()
{
#ifdef _WIN32
  CloseHandle(hMutexLock);
#else
  pthread_mutex_destroy(&MutexLock);
#endif
}

void Mutex::Lock() const
{
#ifdef _WIN32
  DWORD dwResult;

  /* Wait for the mutex to be free */
  dwResult = WaitForSingleObject(hMutexLock, INFINITE);
  switch (dwResult)
  {
    /* Mutex is now free */
    case WAIT_ABANDONED:
    case WAIT_OBJECT_0:
      break;
    /* In case WaitForSignleObject failed */
    case WAIT_FAILED:
      throw 1;
      break;
  }
#else
  /* Wait & lock */
  pthread_mutex_lock((pthread_mutex_t *)&MutexLock);
#endif
}

bool Mutex::TryLock() const
{
#ifdef _WIN32
  bool bRes = false;
  DWORD dwResult;

  /* Acquire the mutex immediatly! */
  dwResult = WaitForSingleObject(hMutexLock, 1);
  switch (dwResult)
  {
    /* Mutex was free */
    case WAIT_ABANDONED:
    case WAIT_OBJECT_0:
      bRes = true;
      break;
    /* Mutex wasn't free */
    case WAIT_TIMEOUT:
    /* In case WaitForSignleObject failed */
    case WAIT_FAILED:
      bRes = false;
      break;
  }
  return bRes;
#else
  /* Try to lock */
  return (!pthread_mutex_trylock((pthread_mutex_t *)&MutexLock));
#endif
}

bool Mutex::Unlock() const
{
  /* Release */
#ifdef _WIN32
  return ReleaseMutex(hMutexLock);
#else
  return (!pthread_mutex_unlock((pthread_mutex_t *)&MutexLock));
#endif
}

