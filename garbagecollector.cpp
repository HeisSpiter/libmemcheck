/*! \file garbagecollector.cpp
 * \brief Garbage Collector implementation file.
 * \author Pierre Schweitzer
 * \copyright Copyright 2011 - 2014. All rights reserved.
 * This project is released under the GNU General Public License version 2.
 *
 * That file contains all the implementations for the garbage collector.
 * Build it when using garbage collector. And include header.
 */

#include "garbagecollector.hpp"

gc::GarbageCollector::GarbageCollector() throw(gc::InternalError)
{
  /* Initialize attributes */
  SetAllocationsLimit();
  SetMemoryLimit();
  uiAllocatedCount = 0;
  uiFreedCount = 0;
  uiWeakCount = 0;
  uiLookasideCount = 0;
  pmbAllocated = 0;
  pmbFreed = 0;
  ulTotalAllocated = 0;

  /* Get system malloc */
  pSystemMalloc = (void * (*)(size_t))dlsym(RTLD_NEXT, "malloc");
  if (pSystemMalloc == 0)
  {
    GCDebug("Failed to get system malloc()");
    throw InternalError();
  }

  pSystemFree = (void (*)(void *))dlsym(RTLD_NEXT, "free");
  if (pSystemFree == 0)
  {
    GCDebug("Failed to get system free()");
    throw InternalError();
  }
}

gc::GarbageCollector::GarbageCollector(const gc::GarbageCollector& inGC) throw()
{
  /* Copy state */
  uListsMaxSize = inGC.uListsMaxSize;
  uiAllocatedCount = inGC.uiAllocatedCount;
  uiFreedCount = inGC.uiFreedCount;
  uiWeakCount = inGC.uiWeakCount;
  uiLookasideCount = inGC.uiLookasideCount;
  pmbAllocated = inGC.pmbAllocated;
  pmbFreed = inGC.pmbFreed;
  ulTotalAllocated = inGC.ulTotalAllocated;
  ulMaxBytes = inGC.ulMaxBytes;
  pSystemMalloc = inGC.pSystemMalloc;
  pSystemFree = inGC.pSystemFree;
}

gc::GarbageCollector::~GarbageCollector()
{
#ifdef _DBG_
  unsigned int Size = 0;
#endif
  GCDebug("Garbadge collector destruction initiated");

  /* Acquire lists lock */
  mListsLock.Lock();

  /* Start with allocated blocks */
  MemoryBlock * CurrentBlock = pmbAllocated;

  /* First of all, release everything */
  if (CurrentBlock != 0)
  {
    do
    {
      MemoryBlock * NextBlock = CurrentBlock->pNextBlock;
#ifdef _DBG_
      /* Only consider leaked block if non-weak */
      if (!CurrentBlock->bBlockWeak)
      {
        GCDebug("Releasing leaked " << CurrentBlock->uBlockSize
                << "bytes at address: " << CurrentBlock->pBlock);
        GCDebug("It was referenced " << CurrentBlock->uiBlockReferences << " times");
        GCDebug("Thread " << CurrentBlock->ulBlockOwner << " was owning it");
        GCDebug("It has been allocated at : " << CurrentBlock->pCallingAddress);
        Size += CurrentBlock->uBlockSize;
      }
      /* As we are in debug mode, also perform
       * sanity checks on memory. If they fail
       * do not raise, but inform by printing a
       * message.
       */
      if (!ValidateBlock(CurrentBlock->pBlock, CurrentBlock->uBlockSize))
      {
        GCDebug("Memory zone " << CurrentBlock->pBlock << " seems to have been corrupted, consider checking you program!");
      }
#endif
      FreeBlock(CurrentBlock->pBlock, CurrentBlock->bBlockNonPageable, CurrentBlock->uBlockSize);
      FreeBlock(CurrentBlock, false, sizeof(MemoryBlock), true);
      uiAllocatedCount--;
      CurrentBlock = NextBlock;
    } while (CurrentBlock != pmbAllocated);
  }

#ifdef _DBG_
  GCDebug("Released " << Size << "bytes (32bits aligned) leaked");
#endif

  /* Then, release freed blocks */
  CurrentBlock = pmbFreed;
  if (CurrentBlock != 0)
  {
    do
    {
      MemoryBlock * NextBlock = CurrentBlock->pNextBlock;

      /* Take care of lookaside blocks */
      if (CurrentBlock->bBlockLookaside)
      {
        FreeBlock(CurrentBlock->pBlock, CurrentBlock->bBlockNonPageable, CurrentBlock->uBlockSize);
      }

      FreeBlock(CurrentBlock, false, sizeof(MemoryBlock), true);
      uiFreedCount--;
      CurrentBlock = NextBlock;
    } while (CurrentBlock != pmbFreed);
  }

  /* Release lists and delete lock */
  mListsLock.Unlock();

  GCDebug("Remaining memory allocated: " << ulTotalAllocated << "bytes");
}

void * gc::GarbageCollector::Allocate(size_t Size, unsigned int Flags) throw(gc::InvalidSize, gc::InvalidFlags, gc::ListCorrupted, gc::MemoryBlockCorrupted, gc::NoMemory, gc::NotEnoughSpace)
{
  return AllocateWithTagInt(Size, Flags, 0UL);
}

void * gc::GarbageCollector::AllocateBlock(size_t Size, bool NonPageable, bool ZeroBlock, bool NotExtended, bool MustSucceed) throw(gc::InternalError)
{
  void * MemoryBlock;
  size_t AllocateSize;

  /* This would just be senseless */
  if (MustSucceed)
  {
    GCAssert(NotExtended);
  }

  /* Sanity check... */
  if (!NotExtended)
  {
    GCAssert(Size % sizeof(unsigned int) == 0);
    AllocateSize = GetExtendedSize(Size);
  }
  /* Just allocate what has been asked */
  else
  {
    AllocateSize = Size;
  }

  /* Try to allocate memory */
  MemoryBlock = pSystemMalloc(AllocateSize);
  /* If we have memory block */
  if (MemoryBlock != 0)
  {
    /* Check if user wants zeroed memory */
    if (ZeroBlock)
    {
      memset(MemoryBlock, 0, AllocateSize);
    }

    /* If that's a normal allocation */
    if (!NotExtended)
    {
      /* Mark memory */
      *(unsigned int *)MemoryBlock = UNINIT_MARKER;
      *((unsigned int *)(MemoryBlock) + (Size / sizeof(unsigned int)) + 1) = UNINIT_MARKER;

      /* If it is to non-pageable, lock block */
      if (NonPageable)
      {
        if (!LockBlock(MemoryBlock, AllocateSize, true))
        {
          /* In case of a failure, append 1 to the address */
          MemoryBlock = (void *)((long)MemoryBlock | 1);
        }
      }
    }
  }

  if (!MustSucceed)
  {
    /* Now, increase total allocated size */
    ulTotalAllocated += AllocateSize;
    GCAssert(ulTotalAllocated <= ulMaxBytes);
  }

  return MemoryBlock;
}

void * gc::GarbageCollector::AllocateWithTag(size_t Size, unsigned int Flags, unsigned long Tag) throw(gc::InternalError, gc::InvalidSize, gc::InvalidFlags, gc::MemoryBlockCorrupted, gc::NoMemory, gc::NotEnoughSpace)
{
    return AllocateWithTagInt(Size, Flags, Tag);
}

void * gc::GarbageCollector::AllocateWithTagInt(size_t Size, unsigned int Flags, unsigned long Tag) throw(gc::InternalError, gc::InvalidSize, gc::InvalidFlags, gc::MemoryBlockCorrupted, gc::NoMemory, gc::NotEnoughSpace)
{
  void * Block;
  unsigned int k;
  size_t RealSize;
  MemoryBlock * CurrentBlock = 0, * FirstMatching = 0;

  /* Setup flags vars */
  bool RaiseOnFailure = IsFlagOn(Flags, RAISE_ON_FAILURE);
  bool NonPaged = IsFlagOn(Flags, NON_PAGED_BLOCK);
  bool MustSucceed = IsFlagOn(Flags, MUST_SUCCEED);

  GCDebug("Request for " << Size << "B with flags " << Flags << " and tag " << Tag);

#ifdef _DBG_
  if (MustSucceed)
  {
    GCDebug("MUST_SUCCEED allocation requested. Trying to keep it as normal as possible");
  }
#endif

  /* We cannot allocate 0-sized block */
  if (Size == 0 && !MustSucceed)
  {
    if (RaiseOnFailure)
    {
      throw InvalidSize();
    }
    return 0;
  }

  /* Validate flags:
   * Cannot have ZEROED & MARKED out of MUST_SUCCEED
   */
  if ((IsFlagOn(Flags, ZEROED_BLOCK) && IsFlagOn(Flags, MARKED_BLOCK) && !MustSucceed) ||
      (IsFlagOn(Flags, CACHING_BLOCK) && IsFlagOn(Flags, LOOKASIDE_BLOCK))) /* FIXME: Would deserve attention */
  {
    if (RaiseOnFailure)
    {
      throw InvalidFlags();
    }
    return 0;
  }

  /* Align memory on 32bits for allocation */
  if (Size % sizeof(unsigned int) != 0)
  {
    RealSize = Size + (sizeof(unsigned int) - (Size % sizeof(unsigned int)));
  }
  else
  {
    RealSize = Size;
  }

  /* Acquire linked lists */
  mListsLock.Lock();

  /* In case caller asked for weak block, let's perform some tests */
  if (IsFlagOn(Flags, CACHING_BLOCK) && uiAllocatedCount && !MustSucceed)
  {
    /* If more than 75% of the pool has been allocated, then allocation
     * starts being questionnable.
     * But, if more than 25% of that pool is made of weak blocks, then the
     * new block should have a not that short lifetime.
     * Otherwise, deny allocation, this wouldn't make sense.
     */
    GCAssert(uListsMaxSize != 0);
    if ((uiAllocatedCount * 100 / uListsMaxSize > 75) &&
        (!uiWeakCount || uiWeakCount * 100 / uiAllocatedCount < 25))
    {
      if (RaiseOnFailure)
      {
        throw NotEnoughSpace();
      }
      return 0;
    }
  }

  /* User wants lookaside block, and there are some */
  if (IsFlagOn(Flags, LOOKASIDE_BLOCK) && uiLookasideCount > 0)
  {
    GCAssert(pmbFreed != 0);

    /* Start with oldest*/
    CurrentBlock = pmbFreed->pPrevBlock;
    /* The idea of this algorithm is quite easy.
     * The purpose is to find an already allocated block
     * that matches caller needs.
     * First, we try to find a block that has exactly the
     * right size.
     * If that fails, we try to find a block that can contain
     * caller block.
     * Instead of doing two list loops, we sum up in once:
     * - If a block that can match caller needs, we save it
     *   and continue looping.
     * - If a block is exact size, we save it and quit loop.
     * That way, when we quit loop we have either: no block,
     * perfect block first, or block that can match if nothing
     * else available.
     */
    do
    {
      /* If block is lookaside & its size can contain what caller wants */
      if (CurrentBlock->bBlockLookaside && CurrentBlock->uBlockSize >= RealSize)
      {
        /* Select if none yet that block as possible choice */
        if (FirstMatching == 0)
        {
          FirstMatching = CurrentBlock;
        }

        /* If block is perfectly matching what caller wants, return it */
        if (CurrentBlock->uBlockSize == RealSize)
        {
          FirstMatching = CurrentBlock;
          break;
        }
      }

      CurrentBlock = CurrentBlock->pPrevBlock;
    } while (CurrentBlock != pmbFreed->pPrevBlock);

    /* If there is block available */
    if (FirstMatching != 0)
    {
      /* Unlink it and present it */
      CurrentBlock = FirstMatching;
      UnlinkEntry(&pmbFreed, CurrentBlock);
      CurrentBlock->pNextBlock = 0;
      CurrentBlock->pPrevBlock = 0;
      uiFreedCount--;
      uiLookasideCount--;
    }
  }

  /* We cannot allocate if we are already full */
  if ((uiAllocatedCount == uListsMaxSize || ulTotalAllocated + GetExtendedSize(RealSize) + sizeof(MemoryBlock) > ulMaxBytes) &&
      CurrentBlock == 0)
  {
    bool FoundBlock = false;

    /* Try to see whether there are weak blocks */
    if (uiWeakCount > 0)
    {
      /* Browse the allocated list, find the first weak block
       * and free it
       */
      GCAssert(pmbAllocated != 0);
      CurrentBlock = pmbAllocated->pPrevBlock;
      do
      {
        /* Found weak block */
        if (CurrentBlock->bBlockWeak)
        {
          /* Prepare for immediate re-use */
          if (!ValidateBlock(CurrentBlock->pBlock, CurrentBlock->uBlockSize))
          {
            throw MemoryBlockCorrupted();
            return 0;
          }

          FreeBlock(CurrentBlock->pBlock, CurrentBlock->bBlockNonPageable, CurrentBlock->uBlockSize);
          uiAllocatedCount--;
          uiWeakCount--;
          FoundBlock = true;
          break;
        }

        CurrentBlock = CurrentBlock->pPrevBlock;
      } while (CurrentBlock != pmbAllocated->pPrevBlock);
    }

    /* If no block was found and allocation list can still contain
     * entries, then try to get a block from freed list (only if
     * it can help)
     */
    if (!FoundBlock && uiAllocatedCount != uListsMaxSize &&
        pmbFreed != 0 && ulTotalAllocated + GetExtendedSize(RealSize) <= ulMaxBytes &&
        uiFreedCount > uiLookasideCount)
    {
      /* Find first non lookaside block */
      CurrentBlock = pmbFreed->pPrevBlock;
      do
      {
        if (!CurrentBlock->bBlockLookaside)
        {
          break;
        }

        CurrentBlock = CurrentBlock->pPrevBlock;
      } while (CurrentBlock != pmbFreed->pPrevBlock);

      GCAssert(!CurrentBlock->bBlockLookaside);

      /* Unlink */
      UnlinkEntry(&pmbFreed, CurrentBlock);
      CurrentBlock->pNextBlock = 0;
      CurrentBlock->pPrevBlock = 0;
      uiFreedCount--;
      FoundBlock = true;
    }

    /* Definitely no space remaining */
    if (!FoundBlock || ulTotalAllocated + GetExtendedSize(RealSize) > ulMaxBytes)
    {
      /* If that point is reached, with a block
       * it means that we are hitting a quota
       * Get rid of block
       */
      if (FoundBlock)
      {
        UnlinkEntry(&pmbAllocated, CurrentBlock);
        FreeBlock(CurrentBlock, false, sizeof(MemoryBlock), true);
      }

      mListsLock.Unlock();
      if (MustSucceed)
      {
        /* We are in must succeed mode. User absolutely wants a memory
         * block even if we cannot store it in the allocated linked list.
         * In such situation, behaviour is easy: we will simply allocate
         * a normal block using new and return it to the user.
         * We even do not try to align its size, this would be
         * senseless.
         */
        GCDebug("Attempting to allocate a block that won't be added to internal structures");
        Block = AllocateBlock(Size, false, IsFlagOn(Flags, ZEROED_BLOCK), true, true);
        if (Block != 0)
        {
          /* User asked for initialized memory, that we can do */
          if (IsFlagOn(Flags, MARKED_BLOCK))
          {
            unsigned int Position;

            /* Write as much as we can */
            for (k = 0; k < Size / sizeof(unsigned int); k++)
            {
              ((unsigned int*)Block)[k] = UNINIT_MARKER;
            }
            Position = k * sizeof(unsigned int);
            /* Complete if needed */
            if (Position < Size)
            {
              for (k = 0; k < Size; k++)
              {
                (((unsigned char*)Block) + Position)[k] = 0xdd;
              }
            }
          }
#ifdef _DBG_
          /* We are in debug mode, flood a bit about the allocated block */
          if (NonPaged)
          {
            GCDebug("User asked a NON_PAGED_BLOCK, no way we provide it");
          }
          if (IsFlagOn(Flags, OWNER_LOCK))
          {
            GCDebug("User asked for OWNER_LOCK, no way we provide it");
          }
          if (IsFlagOn(Flags, CACHING_BLOCK))
          {
            GCDebug("User asked for CACHING_BLOCK, no way we provide it");
          }
          GCDebug("¡Returning unkown MUST_SUCCEED memory block!");
#endif
          return Block;
        }
        GCDebug("MUST_SUCCEED block allocation failed, there's nothing more we can do...");
        throw NoMemory();
      }
      else if (RaiseOnFailure)
      {
        throw NotEnoughSpace();
      }
      GCDebug("Out of memory!");
      return 0;
    }
  }

  if (CurrentBlock == 0)
  {
    /* If free space is full, then take entry there
     * Also take there if free space twice bigger
     * than allocated space.
     * This may offer weak blocks a bit bigger lifetime
     */
    if ((uiFreedCount >= uListsMaxSize || (uiAllocatedCount && (uiFreedCount / uiAllocatedCount >= 2))) &&
        uiFreedCount > uiLookasideCount)
    {
      GCAssert(pmbFreed != 0);

      /* Find first non lookaside block */
      CurrentBlock = pmbFreed->pPrevBlock;
      do
      {
        if (!CurrentBlock->bBlockLookaside)
        {
          break;
        }

        CurrentBlock = CurrentBlock->pPrevBlock;
      } while (CurrentBlock != pmbFreed->pPrevBlock);

      GCAssert(!CurrentBlock->bBlockLookaside);

      /* Unlink */
      UnlinkEntry(&pmbFreed, CurrentBlock);
      CurrentBlock->pNextBlock = 0;
      CurrentBlock->pPrevBlock = 0;
      uiFreedCount--;
    }
    else
    {
      /* If we are not using old entry, then allocate */
      CurrentBlock = (MemoryBlock *)AllocateBlock(sizeof(MemoryBlock), false, true, true);
      if (CurrentBlock == 0)
      {
        mListsLock.Unlock();
        /* Assume that we even cannot allocate a memory block, then
         * there is nothing that can be done
         */
        if (RaiseOnFailure)
        {
          throw NoMemory();
        }
        return 0;
      }
    }
  }

  /* Lookaside block found */
  if (!CurrentBlock->bBlockFreed && !CurrentBlock->bBlockWeak && CurrentBlock->pBlock != 0)
  {
    GCAssert(IsFlagOn(Flags, LOOKASIDE_BLOCK));

    /* Handle a bad quota here */
    if (uiAllocatedCount == uListsMaxSize && !MustSucceed)
    {
      /* Cannot continue, relink and quit */
      LinkEntry(&pmbFreed, CurrentBlock);
      uiFreedCount++;
      uiLookasideCount++;

      if (RaiseOnFailure)
      {
        throw NoMemory();
      }
      return 0;
    }

    /* Get block address */
    Block = CurrentBlock->pBlock;
    /* Get real size (in case it is bigger than caller needs) */
    RealSize = CurrentBlock->uBlockSize;
    /* Zero block */
    memset((unsigned int *)Block + 1, 0, RealSize);

    /* Unlock if required */
    if (CurrentBlock->bBlockNonPageable && !NonPaged)
    {
      (void)UnlockBlock(Block, RealSize);
    }
    /* Lock if required */
    else if (!CurrentBlock->bBlockNonPageable && NonPaged)
    {
      /* Try locking */
      if (!LockBlock(Block, RealSize))
      {
        NonPaged = false;

        if (!MustSucceed)
        {
          /* Do NOT free anything here
           * Get back all the stuff in freed list
           * and fail nicely
           */
          LinkEntry(&pmbFreed, CurrentBlock);
          uiFreedCount++;
          uiLookasideCount++;

          mListsLock.Unlock();

          if (RaiseOnFailure)
          {
            throw NoMemory();
          }
          return 0;
        }
      }
    }

    /* Handle bad quota II */
    if (uiAllocatedCount == uListsMaxSize)
    {
      GCAssert(MustSucceed);
      GCDebug("Releasing block " << Block << " from garbage collector!");

      /* We cannot put block in list, BUT
       * caller wants block.
       * Let's start tricky stuff
       */

      /* First of all, get rid of GC block */
      FreeBlock(CurrentBlock, false, sizeof(MemoryBlock), true);

      /* Unlock block if required */
      if (NonPaged)
      {
        (void)UnlockBlock(Block, RealSize);
      }

      /* Zero the whole block */
      memset(Block, 0, GetExtendedSize(RealSize));

      /* This block does not exist anylonger for GC */
      ulTotalAllocated -= GetExtendedSize(RealSize);

      mListsLock.Unlock();

      /* Return it */
      return Block;
    }

    /* Once here, everything is done.
     * CurrentBlock just looks like any other block.
     */
  }
  else
  {
    /* Allocate new memory block */
    Block = AllocateBlock(RealSize, NonPaged, IsFlagOn(Flags, ZEROED_BLOCK));
    /* If the address is odd, an error occured */
    if ((long)Block & 1)
    {
      /* The caller was asking for non paged block, and it failed */
      GCAssert(NonPaged);

      GCDebug("Locking block in memory failed!");

      /* Get real address */
      Block = (void *)((long)Block & ~1);
      /* Ignore caller desire, and set reality */
      NonPaged = false;

      /* MUST_SUCCEED was not provide, we can refuse allocation */
      if (!MustSucceed)
      {
        /* Release and prepare fallback in next if */
        FreeBlock(Block, false, RealSize);
        Block = 0;
      }
    }
    if (Block == 0)
    {
      /* Unlink entry if required */
      if (CurrentBlock->pNextBlock != 0)
      {
        GCAssert(CurrentBlock->pPrevBlock != 0);
        UnlinkEntry(&pmbAllocated, CurrentBlock);
      }

      mListsLock.Unlock();

      /* Release entry */
      FreeBlock(CurrentBlock, false, sizeof(MemoryBlock), true);

      if (RaiseOnFailure)
      {
        throw NoMemory();
      }
      return 0;
    }
  }

  /* Update status */
  uiAllocatedCount++;
  CurrentBlock->pBlock = Block;
  CurrentBlock->uBlockSize = RealSize;
  CurrentBlock->ulBlockTag = Tag;
  CurrentBlock->bBlockFreed = false;

  /* Did caller wanted a non-paged block? */
  CurrentBlock->bBlockNonPageable = NonPaged;

  /* Did caller asked for owner lock? */
  CurrentBlock->ulBlockOwner = IsFlagOn(Flags, OWNER_LOCK) ? GetThreadID() : 0;

  /* Did caller asked for weak block? */
  CurrentBlock->bBlockWeak = IsFlagOn(Flags, CACHING_BLOCK);
  if (CurrentBlock->bBlockWeak)
  {
    uiWeakCount++;
  }

  /* Did caller asked for lookaside block? */
  CurrentBlock->bBlockLookaside = IsFlagOn(Flags, LOOKASIDE_BLOCK);

  /* Did caller asked for initialized block? */
  if (IsFlagOn(Flags, MARKED_BLOCK))
  {
    for (k = 1; k <= Size / sizeof(unsigned int); k++)
    {
      ((unsigned int*)Block)[k] = UNINIT_MARKER;
    }
  }

  /* Who's the requester?
   * We use 1 here, because 0 is a function of our library
   */
  CurrentBlock->pCallingAddress = __builtin_return_address(1);

  /* If required, insert entry in list */
  if (CurrentBlock->pNextBlock == 0)
  {
    GCAssert(CurrentBlock->pPrevBlock == 0);
    LinkEntry(&pmbAllocated, CurrentBlock);
  }

  /* Release linked lists */
  mListsLock.Unlock();

  GCDebug("Allocated " << RealSize << "bytes at address: " << Block);
  GCDebug("Returning address " << (void*)((unsigned int *)Block + 1));

  return (void *)((unsigned int *)Block + 1);
}

void gc::GarbageCollector::CheckForCorruption() const throw(gc::ListCorrupted, gc::MemoryBlockCorrupted)
{
  unsigned long TotalMemory = 0;
  unsigned int TotalEntries = 0, WeakEntries = 0, LookasideEntries = 0;

  /* Acquire lists */
  mListsLock.Lock();

  MemoryBlock * CurrentBlock = pmbAllocated;

  /* We will first browse allocated memory */
  try
  {
    if (CurrentBlock != 0)
    {
      do
      {
        /* If it is in use, then it has an address and a size and it exists */
        if (CurrentBlock->pBlock == 0 ||
            CurrentBlock->uBlockSize == 0 ||
            CurrentBlock->bBlockFreed == true)
        {
          GCDebug("In use entry " << CurrentBlock << " seems to be corrupted!");
          GCDebug("It may have been allocated at: " << CurrentBlock->pCallingAddress);
          mListsLock.Unlock();
          throw ListCorrupted();
        }

        /* In case we have an entry in use, really check
         * the pointed memory area.
         */
        if (!ValidateBlock(CurrentBlock->pBlock, CurrentBlock->uBlockSize))
        {
          /* Not valid! */
          GCDebug("Memory block at " << CurrentBlock->pBlock << " seems to be corrupted!");
          GCDebug("It may have been allocated at: " << CurrentBlock->pCallingAddress);
          mListsLock.Unlock();
          throw MemoryBlockCorrupted();
        }

        /* Add sizes to total allocated */
        TotalMemory += sizeof(MemoryBlock);
        TotalMemory += GetExtendedSize(CurrentBlock->uBlockSize);

        /* Count entries */
        TotalEntries++;

        if (CurrentBlock->bBlockWeak)
        {
          WeakEntries++;
        }

        CurrentBlock = CurrentBlock->pNextBlock;
      } while (CurrentBlock != pmbAllocated);
    }
  }
  catch (...)
  {
    /* If we reach that point, then something went really bad */
    GCDebug("In use list links lost, consider shutting down program immediately!");
    mListsLock.Unlock();
    throw ListCorrupted();
  }

  /* Check whether there are no too many entries */
  if (TotalEntries > uListsMaxSize)
  {
    mListsLock.Unlock();
    throw ListCorrupted();
  }

  /* Check for counter consistency */
  if (TotalEntries != uiAllocatedCount)
  {
    mListsLock.Unlock();
    throw ListCorrupted();
  }
  if (WeakEntries != uiWeakCount)
  {
    mListsLock.Unlock();
    throw ListCorrupted();
  }

  /* Now, check freed list */
  CurrentBlock = pmbFreed;
  TotalEntries = 0;
  try
  {
    if (CurrentBlock != 0)
    {
      do
      {
        /* If it is freed, then it has an address and a size and it does not exist */
        if (CurrentBlock->pBlock == 0 ||
            CurrentBlock->uBlockSize == 0 ||
            CurrentBlock->bBlockFreed == false)
        {
          GCDebug("Freed entry " << CurrentBlock << " seems to be corrupted!");
          GCDebug("It may have been allocated at: " << CurrentBlock->pCallingAddress);
          mListsLock.Unlock();
          throw ListCorrupted();
        }

        /* Add size to total allocated */
        TotalMemory += sizeof(MemoryBlock);

        /* Handle lookaside blocks */
        if (CurrentBlock->bBlockLookaside)
        {
          TotalMemory += GetExtendedSize(CurrentBlock->uBlockSize);
          LookasideEntries++;
        }

        /* Count entries */
        TotalEntries++;

        CurrentBlock = CurrentBlock->pNextBlock;
      } while (CurrentBlock != pmbFreed);
    }
  }
  catch (...)
  {
    /* If we reach that point, then something went really bad */
    GCDebug("In use list links lost, consider shutting down program immediately!");
    mListsLock.Unlock();
    throw ListCorrupted();
  }

  /* Check against data being non-consistent */
  if (TotalMemory != ulTotalAllocated)
  {
    mListsLock.Unlock();
    throw ListCorrupted();
  }
  if (TotalMemory > ulMaxBytes)
  {
    mListsLock.Unlock();
    throw ListCorrupted();
  }

  /* Check for counter consistency */
  if (TotalEntries != uiFreedCount)
  {
    mListsLock.Unlock();
    throw ListCorrupted();
  }
  if (LookasideEntries != uiLookasideCount)
  {
    mListsLock.Unlock();
    throw ListCorrupted();
  }

  mListsLock.Unlock();

  /* If we reached that point, all correct! */
  return;
}

void gc::GarbageCollector::Dereference(void * Address) throw(gc::InternalError, gc::TooMuchSpace, gc::InvalidAddress, gc::ListCorrupted, gc::InvalidTag, gc::WrongFreer, gc::MemoryBlockCorrupted)
{
  MemoryBlock * CurrentBlock;

  /* Lock lists */
  mListsLock.Lock();

  /* Try to find the address */
  try
  {
    CurrentBlock = FindBlock(Address, true);
  }
  /* We will not throw for that */
  catch(GCException& e)
  {
    mListsLock.Unlock();
    return;
  }

  /* Passed that point, everything must be OK! */
  GCAssert(CurrentBlock);

  /* Check for references */
  if (CurrentBlock->uiBlockReferences != 0)
  {
    /* If present, dereference */
    CurrentBlock->uiBlockReferences--;
  }

  /* If no references, block is now useless, free it */
  if (CurrentBlock->uiBlockReferences == 0)
  {
    /* Release lock to permit FreeWithTag to retake it */
    mListsLock.Unlock();
    FreeWithTag(Address, CurrentBlock->ulBlockTag);
  }
  else
  {
    mListsLock.Unlock();
  }

  return;
}

gc::GarbageCollector& gc::GetInstance() throw(gc::InternalError)
{
  static GarbageCollector Instance;
  return Instance;
}

gc::GarbageCollector::MemoryBlock * gc::GarbageCollector::FindBlock(const void * UserAddress, bool MustBeValid) const throw(gc::InternalError, gc::TooMuchSpace, gc::InvalidAddress, gc::ListCorrupted)
{
  MemoryBlock * CurrentBlock;
  void * RealAddress;

  /* If we attempt to find address with
   * nothing allocated, something is wrong...
   * Or even if we are passing a null pointer...
   */
  if ((uiAllocatedCount == 0 && MustBeValid) || (uiAllocatedCount == 0 && uiFreedCount == 0 && !MustBeValid))
  {
    /* Raise and quit! */
    throw TooMuchSpace();
    return 0;
  }
  if (UserAddress == 0)
  {
    /* Raise and quit */
    throw InvalidAddress();
    return 0;
  }

  /* Get real address */
  RealAddress = ((unsigned int *)UserAddress - 1);

  try
  {
    /* Search for the address, in allocated first */
    CurrentBlock = pmbAllocated;
    if (CurrentBlock != 0)
    {
      do
      {
        if (CurrentBlock->pBlock == RealAddress)
        {
          GCAssert(CurrentBlock->bBlockFreed != true);
          return CurrentBlock;
        }

        CurrentBlock = CurrentBlock->pNextBlock;
      } while (CurrentBlock != pmbAllocated);
    }
  }
  catch (...)
  {
    /* If anything happens, just throw ListCorrupted, it will match everything */
    throw ListCorrupted();
    return 0;
  }

  /* If we did not find the address */
  if (MustBeValid)
  {
    /* Raise and quit! */
    throw InvalidAddress();
    return 0;
  }

  try
  {
    /* Try to look in freed space */
    CurrentBlock = pmbFreed;
    if (CurrentBlock != 0)
    {
      do
      {
        if (CurrentBlock->pBlock == RealAddress)
        {
          return CurrentBlock;
        }

        CurrentBlock = CurrentBlock->pNextBlock;
      } while (CurrentBlock != pmbFreed);
    }
  }
  catch (...)
  {
    /* If anything happens, just throw ListCorrupted, it will match everything */
    throw ListCorrupted();
    return 0;
  }

  /* If we did not find the address, raise and quit */
  throw InvalidAddress();
  return 0;
}

void gc::GarbageCollector::Free(void * Address) throw(gc::InternalError, gc::TooMuchSpace, gc::InvalidAddress, gc::ListCorrupted, gc::InvalidTag, gc::WrongFreer, gc::MemoryBlockCorrupted)
{
  FreeWithTag(Address, 0UL);

  return;
}

void gc::GarbageCollector::FreeBlock(void * BlockAddress, bool NonPaged, size_t BlockSize, bool IsNotExtended) throw(gc::ListCorrupted)
{
  /* Passed that point, address must be valid */
  GCAssert(BlockAddress != 0);

  size_t AllocatedSize = BlockSize;
  if (!IsNotExtended)
  {
    AllocatedSize = GetExtendedSize(BlockSize);
  }

  /* If memory block was to be non-paged, unlock it */
  if (NonPaged)
  {
    (void)UnlockBlock(BlockAddress, AllocatedSize, true);
  }

  pSystemFree(BlockAddress);

  /* Now, decrease total allocated */
  ulTotalAllocated -= AllocatedSize;

  return;
}

void gc::GarbageCollector::FreeWithTag(void * Address, unsigned long Tag) throw(gc::InternalError, gc::TooMuchSpace, gc::InvalidAddress, gc::ListCorrupted, gc::InvalidTag, gc::WrongFreer, gc::MemoryBlockCorrupted)
{
  MemoryBlock * CurrentBlock;

  GCDebug("Free for address " << Address << " requested");

  /* Lock lists */
  mListsLock.Lock();

  /* Try to find the address */
  try
  {
    CurrentBlock = FindBlock(Address, true);
  }
  /* Ensure lock is released before throwing */
  catch(GCException& e)
  {
    mListsLock.Unlock();
    throw;
  }

  /* Passed that point, everything must be OK! */
  GCAssert(CurrentBlock != 0);

  /* Check against matching tag */
  if (Tag != 0 && CurrentBlock->ulBlockTag != Tag)
  {
    mListsLock.Unlock();
    throw InvalidTag();
  }

  /* Check against matching owner */
  if (CurrentBlock->ulBlockOwner != 0 &&
      CurrentBlock->ulBlockOwner != GetThreadID())
  {
    mListsLock.Unlock();
    throw WrongFreer();
  }

  /* Check against memory corruption */
  if (!ValidateBlock(CurrentBlock->pBlock, CurrentBlock->uBlockSize))
  {
    /* Not valid! */
    mListsLock.Unlock();
    throw MemoryBlockCorrupted();
  }

#ifdef _DBG_
  /* We are in debug mode, let us do more work */
  if (CurrentBlock->uiBlockReferences > 0)
  {
    GCDebug("Leaking " << CurrentBlock->uiBlockReferences << " references"
            << " for block " << CurrentBlock->pBlock);
  }
#endif

  if (!CurrentBlock->bBlockLookaside)
  {
    /* Free memory only if that is not a lookaside block */
    FreeBlock(CurrentBlock->pBlock, CurrentBlock->bBlockNonPageable, CurrentBlock->uBlockSize);
    CurrentBlock->bBlockFreed = true;
  }
  else
  {
    /* Else, keep everything */
    uiLookasideCount++;
  }

  /* Unlink entry */
  UnlinkEntry(&pmbAllocated, CurrentBlock);

  /* If the block was a weak block, one less */
  if (CurrentBlock->bBlockWeak)
  {
    uiWeakCount--;
  }

  /* Move block to freed list */
  LinkEntry(&pmbFreed, CurrentBlock);

  /* Finally, update... */
  uiAllocatedCount--;
  uiFreedCount++;

  /* Release lists and return */
  mListsLock.Unlock();
  return;
}

unsigned long gc::GarbageCollector::GetThreadID() const throw()
{
  /* It is not exported by GLibc */
  return (unsigned long)syscall(SYS_gettid);
}

unsigned long gc::GarbageCollector::GetTotalAllocated() const throw()
{
  return ulTotalAllocated;
}

bool gc::GarbageCollector::IsAddressValid(const void * Address, bool IsInBlock) const throw()
{
  /* Lock lists */
  mListsLock.Lock();

  if (!IsInBlock)
  {
    /* In case address has to be exact, just use internal function */
    try
    {
      (void)FindBlock(Address, true);
      mListsLock.Unlock();
      return true;
    }
    catch (GCException& e)
    {
      mListsLock.Unlock();
      return false;
    }
  }

  MemoryBlock * CurrentBlock;

  /* If we attempt to find address with
   * nothing allocated, something is wrong...
   * Or even if we are passing a null pointer...
   */
  if (uiAllocatedCount == 0 || Address == 0)
  {
    mListsLock.Unlock();
    return false;
  }

  try
  {
    CurrentBlock = pmbAllocated;
    do
    {
      if ((unsigned int *)CurrentBlock->pBlock + 1 <= Address &&
          (unsigned int *)CurrentBlock->pBlock + (CurrentBlock->uBlockSize / sizeof(unsigned int)) >= Address)
      {
        return true;
      }
      CurrentBlock = CurrentBlock->pNextBlock;
    } while (CurrentBlock != pmbAllocated);
  }
  catch (...)
  {
    mListsLock.Unlock();
    /* Should not we inform about such situation? */
    return false;
  }

  mListsLock.Unlock();
  return false;
}

void gc::GarbageCollector::LinkEntry(MemoryBlock ** ListHead, MemoryBlock * Entry) throw()
{
  if (*ListHead != 0)
  {
    Entry->pNextBlock = *ListHead;
    Entry->pPrevBlock = (*ListHead)->pPrevBlock;
    (*ListHead)->pPrevBlock->pNextBlock = Entry;
    (*ListHead)->pPrevBlock = Entry;
  }
  else
  {
    Entry->pNextBlock = Entry;
    Entry->pPrevBlock = Entry;
  }
  *ListHead = Entry;

  return;
}

bool gc::GarbageCollector::LockBlock(void * BlockAddress, size_t BlockSize, bool IsNotExtended) throw(gc::InternalError)
{
  size_t AllocateSize;

  /* Passed that point, address must be valid */
  GCAssert(BlockAddress != 0);

  /* Sanity check... */
  if (!IsNotExtended)
  {
    GCAssert(BlockSize % sizeof(unsigned int) == 0);
    AllocateSize = GetExtendedSize(BlockSize);
  }
  else
  {
    AllocateSize = BlockSize;
  }

  return mlock(BlockAddress, AllocateSize) == 0;
}

gc::GarbageCollector& gc::GarbageCollector::operator=(const GarbageCollector &inGC) throw(gc::ListCorrupted, gc::MemoryBlockCorrupted)
{
  if (this != &inGC)
  {
    /* We first check integrity of old GC
     * If it is not OK, we will do nothing!
     */
    CheckForCorruption();

    /* Then if everything is OK, we delete old GC */
    this->~GarbageCollector();

    /* And we recreate it using given GC */
    /* Copy state */
    uListsMaxSize = inGC.uListsMaxSize;
    uiAllocatedCount = inGC.uiAllocatedCount;
    uiFreedCount = inGC.uiFreedCount;
    uiWeakCount = inGC.uiWeakCount;
    uiLookasideCount = inGC.uiLookasideCount;
    pmbAllocated = inGC.pmbAllocated;
    pmbFreed = inGC.pmbFreed;
    ulTotalAllocated = inGC.ulTotalAllocated;
    ulMaxBytes = inGC.ulMaxBytes;
    pSystemMalloc = inGC.pSystemMalloc;
    pSystemFree = inGC.pSystemFree;
  }

  return *this;
}

void * gc::GarbageCollector::Reallocate(void * Address, size_t Size) throw (gc::InvalidSize, gc::InvalidFlags, gc::ListCorrupted, gc::MemoryBlockCorrupted, gc::NoMemory, gc::NotEnoughSpace, gc::TooMuchSpace, gc::InvalidAddress, gc::InvalidTag, gc::WrongFreer)
{
  return ReallocateWithTag(Address, Size, 0UL);
}

void * gc::GarbageCollector::ReallocateWithTag(void * Address, size_t Size, unsigned long Tag) throw (gc::InternalError, gc::InvalidSize, gc::InvalidFlags, gc::ListCorrupted, gc::MemoryBlockCorrupted, gc::NoMemory, gc::NotEnoughSpace, gc::TooMuchSpace, gc::InvalidAddress, gc::InvalidTag, gc::WrongFreer)
{
  void * Block;
  size_t RealSize;
  bool Valid = true;
  MemoryBlock * CurrentBlock;

  GCDebug("Reallocate for address " << Address << " requested");

  /* In case caller is passing null address, -> allocate */
  if (Address == 0)
  {
    return AllocateWithTagInt(Size, PAGED_BLOCK, Tag);
  }

  /* In case caller did not provide size, -> free */
  if (Size == 0)
  {
    FreeWithTag(Address, Tag);
    return 0;
  }

  /* Lock lists */
  mListsLock.Lock();

  /* Try to find the address */
  try
  {
    CurrentBlock = FindBlock(Address, true);
  }
  catch(GCException& e)
  {
    Valid = false;
  }

  /* Try to find the address in freed addresses */
  try
  {
    CurrentBlock = FindBlock(Address, false);
  }
  /* We cannot continue without an address */
  catch(GCException& e)
  {
    mListsLock.Unlock();
    return 0;
  }

  /* Passed that point, everything must be OK! */
  GCAssert(CurrentBlock);

  /* Align size on 32bits */
  if (Size % sizeof(unsigned int) != 0)
  {
    RealSize = Size + (sizeof(unsigned int) - (Size % sizeof(unsigned int)));
  }
  else
  {
    RealSize = Size;
  }

  if (Valid)
  {
    /* Check against matching tag */
    if (CurrentBlock->ulBlockTag != Tag)
    {
      mListsLock.Unlock();
      return 0;
    }

    /* Check against matching owner */
    if (CurrentBlock->ulBlockOwner != 0 &&
        CurrentBlock->ulBlockOwner != GetThreadID())
    {
      mListsLock.Unlock();
      return 0;
    }

    /* Check if really allocated size matches demanded size, then return */
    if (CurrentBlock->uBlockSize == RealSize)
    {
      mListsLock.Unlock();
      return (void *)((unsigned int *)CurrentBlock->pBlock + 1);
    }

    /* Check against memory corruption */
    if (!ValidateBlock(CurrentBlock->pBlock, CurrentBlock->uBlockSize))
    {
      /* Not valid */
      mListsLock.Unlock();
      return 0;
    }

    /* Check if new block size will not hit a quota */
    if (ulTotalAllocated - CurrentBlock->uBlockSize + RealSize > ulMaxBytes)
    {
      /* Not valid */
      mListsLock.Unlock();
      return 0;
    }

#ifdef _DBG_
    /* We are in debug mode, let us do more work */
    if (CurrentBlock->uiBlockReferences > 0)
    {
      GCDebug("Rellocating referenced block (" << CurrentBlock->uiBlockReferences << " references)!");
    }
#endif
  }
  /* Block has been freed */
  else
  {
    if (!CurrentBlock->bBlockFreed)
    {
      /* Handle lookaside blocks properly */
      if (ulTotalAllocated + RealSize - GetExtendedSize(CurrentBlock->uBlockSize) > ulMaxBytes)
      {
        /* Not valid */
        mListsLock.Unlock();
        return 0;
      }

      if (uiAllocatedCount == uListsMaxSize)
      {
        /* Not valid */
        mListsLock.Unlock();
        return 0;
      }

      /* Check if really allocated size matches demanded size, then return */
      if (CurrentBlock->uBlockSize == RealSize)
      {
        /* Remove from freed list */
        UnlinkEntry(&pmbFreed, CurrentBlock);
        uiFreedCount--;
        uiLookasideCount--;

        /* To put in allocated list */
        LinkEntry(&pmbAllocated, CurrentBlock);
        uiAllocatedCount++;

        mListsLock.Unlock();
        return (void *)((unsigned int *)CurrentBlock->pBlock + 1);
      }
    }
    else
    {
      /* Check if new block size will not hit a quota */
      if (ulTotalAllocated + RealSize > ulMaxBytes)
      {
        /* Not valid */
        mListsLock.Unlock();
        return 0;
      }

      if (uiAllocatedCount == uListsMaxSize)
      {
        /* Not valid */
        mListsLock.Unlock();
        return 0;
      }
    }
  }

  /* Allocate new memory block */
  Block = AllocateBlock(RealSize, CurrentBlock->bBlockNonPageable, false);
  if ((long)Block & 1)
  {
    /* For reallocation, we cannot play. If the block cannot be
     * made non-pageable, that is a shame but deny reallocation.
     * This may happen because there are too many locked blocks,
     * including the one we are about to release. But we cannot unlock
     * it before allocating the new one, due to eventual security
     * issues. Sorry, dude!
     */
    Block = (void *)((long)Block & ~1);
    FreeBlock(Block, false, RealSize);
    Block = 0;
  }
  if (Block == 0)
  {
    mListsLock.Unlock();
    return 0;
  }

  if (!CurrentBlock->bBlockFreed)
  {
    /* Copy old data */
    memcpy((void *)((unsigned int *)Block + 1), 
           (void *)((unsigned int *)CurrentBlock->pBlock + 1),
           min(RealSize, CurrentBlock->uBlockSize));

    /* Free old block */
    FreeBlock(CurrentBlock->pBlock, CurrentBlock->bBlockNonPageable, CurrentBlock->uBlockSize);
  }

  /* In case block was freed and reallocated
   * or in case it was a lookaside block
   */
  if (CurrentBlock->bBlockFreed || !Valid)
  {
    /* Update status */
    CurrentBlock->bBlockFreed = false;

    /* Unlink entry */
    UnlinkEntry(&pmbFreed, CurrentBlock);

    /* If block was a weak block, one more */
    if (CurrentBlock->bBlockWeak)
    {
      uiWeakCount++;
    }

    /* If block was a lookaside block, one less */
    if (!Valid)
    {
      uiLookasideCount--;
    }

    /* Move block to allocated list */
    LinkEntry(&pmbAllocated, CurrentBlock);

    uiAllocatedCount++;
    uiFreedCount--;
  }

  /* Update and return */
  CurrentBlock->pBlock = Block;
  CurrentBlock->uBlockSize = RealSize;
  CurrentBlock->ulBlockTag = Tag;

  /* Release lists */
  mListsLock.Unlock();

  /* We are done, return */
  return (void *)((unsigned int *)Block + 1);
}

void gc::GarbageCollector::Reference(void * Address) throw(gc::InternalError)
{
  MemoryBlock * CurrentBlock;

  /* Lock lists */
  mListsLock.Lock();

  /* Try to find the address */
  try
  {
    CurrentBlock = FindBlock(Address, true);
  }
  /* We will not throw for that */
  catch(GCException& e)
  {
    mListsLock.Unlock();
    return;
  }

  /* Passed that point, everything must be OK! */
  GCAssert(CurrentBlock != 0);

  /* All correct, increase reference */
  CurrentBlock->uiBlockReferences++;

  /* Release lists */
  mListsLock.Unlock();

  return;
}

bool gc::GarbageCollector::SetAllocationsLimit(size_t MaxSize) throw()
{
  /* Refuse 0 */
  if (MaxSize == 0)
  {
    return false;
  }

  /* Acquire lists */
  mListsLock.Lock();

  /* If limit is lower than actual, check if it is senseful */
  if (MaxSize < uListsMaxSize && pmbAllocated != 0)
  {
    size_t Entries = 0;
    MemoryBlock * CurrentBlock = pmbAllocated;

    do
    {
      Entries++;
      CurrentBlock = CurrentBlock->pNextBlock;
    } while (CurrentBlock != pmbAllocated);

    if (Entries > MaxSize)
    {
      /* Not setable */
      mListsLock.Unlock();
      return false;
    }
  }

  uListsMaxSize = MaxSize;

  mListsLock.Unlock();
  return true;
}

bool gc::GarbageCollector::SetMemoryLimit(unsigned long MaxSize) throw()
{
  register bool Result = false;

  /* Refuse 0 */
  if (MaxSize == 0)
  {
    return Result;
  }

  /* Acquire lists */
  mListsLock.Lock();

  /* Set only if it is senseful */
  if (MaxSize >= ulTotalAllocated)
  {
    ulMaxBytes = MaxSize;
    Result = true;
  }

  mListsLock.Unlock();
  return Result;
}

void gc::GarbageCollector::UnlinkEntry(MemoryBlock ** ListHead, MemoryBlock * Entry) throw()
{
  Entry->pNextBlock->pPrevBlock = Entry->pPrevBlock;
  Entry->pPrevBlock->pNextBlock = Entry->pNextBlock;
  if (Entry == *ListHead)
  {
    *ListHead = Entry->pNextBlock;
    if (*ListHead == Entry)
    {
      *ListHead = 0;
    }
  }

  return;
}

bool gc::GarbageCollector::UnlockBlock(void * BlockAddress, size_t BlockSize, bool IsNotExtended) throw(gc::InternalError)
{
  size_t AllocateSize;

  /* Passed that point, address must be valid */
  GCAssert(BlockAddress != 0);

  /* Sanity check... */
  if (!IsNotExtended)
  {
    GCAssert(BlockSize % sizeof(unsigned int) == 0);
    AllocateSize = GetExtendedSize(BlockSize);
  }
  else
  {
    AllocateSize = BlockSize;
  }

  return munlock(BlockAddress, AllocateSize) == 0;
}

bool gc::GarbageCollector::ValidateBlock(const void * BlockAddress, size_t Size) const throw(gc::InternalError)
{
  /* Passed that point, address must be valid */
  GCAssert(BlockAddress != 0);

  /* Check against memory corruption */
  if (*((unsigned int *)(BlockAddress)) != UNINIT_MARKER ||
      *((unsigned int *)(BlockAddress) + (Size / sizeof(unsigned int)) + 1) != UNINIT_MARKER)
  {
    /* We did not find first and/or last marker, return false */
    return false;
  }

  return true;
}

/**
 * \internal
 * Macro for C++ delete operator overloads
 * It is a simple wrapper to Free() method.
 */
#define OP_DELETE_NO_THROW       \
  try                            \
  {                              \
    gc::GetInstance().Free(ptr); \
  }                              \
  catch (gc::GCException& e)     \
  {                              \
    return;                      \
  }

void operator delete(void * ptr) throw()
{
  OP_DELETE_NO_THROW;
}

void operator delete[](void * ptr) throw()
{
  OP_DELETE_NO_THROW;
}

void operator delete(void * ptr, const std::nothrow_t&) throw()
{
  OP_DELETE_NO_THROW;
}

void operator delete[](void * ptr, const std::nothrow_t&) throw()
{
  OP_DELETE_NO_THROW;
}

/**
 * \internal
 * Macro for C++ new operator overloads that throw exception.
 * It is a simple wrapper to Allocate() method.
 */
#define OP_NEW_THROW                                                                        \
  try                                                                                       \
  {                                                                                         \
    return gc::GetInstance().AllocateWithTagInt(size, PAGED_BLOCK | RAISE_ON_FAILURE, 0UL); \
  }                                                                                         \
  catch (gc::GCException& e)                                                                \
  {                                                                                         \
    throw std::bad_alloc();                                                                 \
  }

/**
 * \internal
 * Macro for C++ new operator overloads that do not throw exception.
 * It is a simple wrapper to Allocate() method.
 */
#define OP_NEW_NO_THROW                                                                     \
  try                                                                                       \
  {                                                                                         \
    return gc::GetInstance().AllocateWithTagInt(size, PAGED_BLOCK | RAISE_ON_FAILURE, 0UL); \
  }                                                                                         \
  catch (gc::GCException& e)                                                                \
  {                                                                                         \
    return 0;                                                                               \
  }

void * operator new(std::size_t size) throw (std::bad_alloc)
{
  OP_NEW_THROW;
}

void * operator new[](std::size_t size) throw (std::bad_alloc)
{
  OP_NEW_THROW;
}

void * operator new(std::size_t size, const std::nothrow_t&) throw()
{
  OP_NEW_NO_THROW;
}

void * operator new[](std::size_t size, const std::nothrow_t&) throw()
{
  OP_NEW_NO_THROW;
}

void * calloc(size_t nmemb, size_t size) throw()
{
  /* Simple wrapper */
  try
  {
    return gc::GetInstance().AllocateWithTagInt(nmemb * size, PAGED_BLOCK | RAISE_ON_FAILURE | ZEROED_BLOCK, 0UL);
  }
  catch (gc::GCException& e)
  {
    return 0;
  }
}

void free(void * ptr) throw()
{
  /* Simple wrapper */
  try
  {
    gc::GetInstance().Free(ptr);
  }
  catch (gc::GCException& e)
  {
    return;
  }
}

void * malloc(size_t size) throw()
{
  /* Simple wrapper */
  try
  {
    return gc::GetInstance().AllocateWithTagInt(size, PAGED_BLOCK | RAISE_ON_FAILURE, 0UL);
  }
  catch (gc::GCException& e)
  {
    return 0;
  }
}

void * realloc(void * ptr, size_t size) throw()
{
  /* Simple wrapper */
  try
  {
    return gc::GetInstance().Reallocate(ptr, size);
  }
  catch (gc::GCException& e)
  {
    return 0;
  }
}
