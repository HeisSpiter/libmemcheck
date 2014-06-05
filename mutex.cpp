/*! \file mutex.cpp
 * \brief Mutex implementation file.
 * \author Pierre Schweitzer
 * \copyright Copyright 2011 - 2014. All rights reserved.
 * This project is released under the GNU General Public License version 2.
 *
 * That file contains all the implementations for the mutex.
 * Build it when using mutex. And include header.
 */


#include "mutex.hpp"

Mutex::Mutex()
{
  /* Simple init */
  pthread_mutex_init(&MutexLock, 0);
}

Mutex::~Mutex()
{
  pthread_mutex_destroy(&MutexLock);
}

void Mutex::Lock() const
{
  /* Wait & lock */
  pthread_mutex_lock((pthread_mutex_t *)&MutexLock);
}

bool Mutex::TryLock() const
{
  /* Try to lock */
  return (!pthread_mutex_trylock((pthread_mutex_t *)&MutexLock));
}

bool Mutex::Unlock() const
{
  /* Release */
  return (!pthread_mutex_unlock((pthread_mutex_t *)&MutexLock));
}

