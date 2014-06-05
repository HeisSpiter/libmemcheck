#ifndef _GARBAGECOLLECTOR_H_
#define _GARBAGECOLLECTOR_H_

/*! \file garbagecollector.hpp
 * \brief Garbage collector definition header.
 * \author Pierre Schweitzer
 * \copyright Copyright 2011 - 2014. All rights reserved.
 * This project is released under the GNU General Public License version 2.
 *
 * That file contains all the definitions needed to successfully use the garbage collector.
 * To use the garbage collector in an application, just include garbagecollector.hpp and build garbagecollector.cpp
 */

#include <new>
#include <cstring>
#include <exception>
#include <cstdlib>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <dlfcn.h>
#include "mutex.hpp"
#define _DBG_
#ifdef _DBG_
#include <iostream>
#endif

/**
 * \brief Namespace for the Garbage Collector
 *
 * This namespace contains the garbage collector implementation
 * and all the required defines. Feel free to use using namespace gc;
 * in your code.
 *
 */
namespace gc
{
  /**
   * Initial lists maximum size.
   */
  #define INIT_LISTS_SIZE (size_t)0xa

  /**
   * Initial memory limit. Matches 2Mb.
   */
  #define INIT_MEM_SIZE (unsigned long)0x800

  /**
   * Used to define no limitation for allocations/memory.
   */
  #define LIMIT_UNLIMITED (unsigned)~0

  /**
   * Marker for uninit & unused memory by user
   * It's used by garbage collector to detect
   * any memory corruption that may occur.
   * Of course, that number is odd.
   */
  #define UNINIT_MARKER (unsigned int)0xbaaadbed

  /**
   * Flag for allocation. It means that the block
   * you are requesting can be paged by the OS.
   * That is the default flag.
   */
  #define PAGED_BLOCK      0x0
  /**
   * Flag for allocation. It means that the block
   * you are requesting cannot be paged by the OS.
   */
  #define NON_PAGED_BLOCK  0x1
  /**
   * Flag for allocation. It means that if an error
   * occurs while try trying to allocate the block
   * an exception will be thrown. It is up to you
   * to catch it.
   */
  #define RAISE_ON_FAILURE 0x2
  /**
   * Flag for allocation. It means that the allocation must
   * succed, whatever may raise during allocation.
   * Use it only for critical memory blocks that you
   * absolutely need.
   * Before using it, consider reading AllocateWithTag() documentation
   * and to fully understand it including the associated risks.
   */
  #define MUST_SUCCEED     0x6
  /**
   * Flag for allocation. It means that only the thread that allocated
   * the block can free it.
   */
  #define OWNER_LOCK       0x8
  /**
   * Flag for allocation. It means that the block will be filled in
   * with 0 before it is returned.
   */
  #define ZEROED_BLOCK     0x10
  /**
   * Flag for allocation. It means that the block will be filled in
   * with predefined data before it is returned.
   */
  #define MARKED_BLOCK     0x20
  /**
   * Flag for allocation. It means that the block won't stay in memory
   * forever and will be automatically freed
   */
  #define CACHING_BLOCK    0x40
  /**
   * Flag for allocation. It means that the block will remain in memory
   * even after a free. Reallocation will be faster
   */
  #define LOOKASIDE_BLOCK  0x90

  /**
   * Small and obvious macro to find
   * which number is minimal
   * @param a First number to compare.
   * @param b Second number to compare.
   * @return Biggest of the two numbers
   */
  template<typename T>
  static inline T min(T a, T b)
  {
    return ((a > b) ? b : a);
  }

  /**
   * Macro designed to be used for alpha
   * TAGs for allocation. Just set the letters
   * you want to use as tag.
   */
  #define TAG(a, b, c, d) \
    ((a) + (b << 2) + (c << 4) + (d << 6))

  /**
   * Macro designed to check whether a flag is
   * set on a variable.
   * @param Flags List of flags.
   * @param Flag Flag to check.
   * @return true is the flag is set, false otherwise
   */
  static inline bool IsFlagOn(unsigned int Flags, unsigned int Flag)
  {
    return ((Flags & Flag) == Flag);
  }

  /**
   * \internal
   * Macro for getting the real size of an extended block
   * @param Size Initial size.
   * @return Extended size
   */
  static inline size_t GetExtendedSize(size_t Size)
  {
    return (Size + (sizeof(unsigned int) << 1));
  }

  /**
   * \internal
   * Generic macro used to lazy-define garbage collector
   * exceptions. You shouldn't need it.
   */
  #define DefineException(name, msg)                \
    class name : public GCException {               \
      public:                                       \
        name() throw() { }                          \
        virtual ~name() throw() { };                \
        virtual const char * what() const throw() { \
          return msg;                               \
        }                                           \
    }

  /**
   * \internal
   * Generic macro used to lazy-declare garbage collector
   * exceptions. You shouldn't need it.
   */
  #define DeclareException(name) \
    gc::_##name name

  /**
   * \internal
   * Macro used for debug. Its purpose is to print given
   * expression to standard output. It prepends file, line
   * and function information.
   */
#ifdef _DBG_
  #define GCDebug(exp)                                    \
    std::cout << __FILE__ << ":" << __LINE__ << ": ";     \
    std::cout << __FUNCTION__ << ": " << exp << std::endl
#else
  #define GCDebug(exp)
#endif

  /**
   * Garbage collector assert. If the given expression
   * is false, then a ListCorrupted exception is thrown.
   * Those asserts are automatically activated in debug
   * mode and display a message.
   * In release mode, you can silent them by using build
   * flag -D_NO_ASSERT_
   */
#ifdef _DBG_
  #define GCAssert(exp)                             \
    if (!(exp))                                     \
    {                                               \
      GCDebug("Assertion '" << #exp << "' failed"); \
      throw ListCorrupted();                        \
    }
#else
#ifndef _NO_ASSERT_
  #define GCAssert(exp)                                \
    if (!(exp))                                        \
    {                                                  \
      throw ListCorrupted();                           \
    }
#else
  #define GCAssert(exp)
#endif
#endif

  /**
   * \brief Generic class for garbage collector exceptions
   *
   * This is the base of each garbage collector exception.
   * Use it in your try/catch blocks if you are too lazy to
   * read docs ;-).
   * This exception itself is never thrown.
   * It is based on standard exceptions.
   */
  class GCException : public std::exception
  {
    public:
      GCException() throw() { };
      virtual ~GCException() throw() { };
      virtual const char * what() const throw() = 0;
  };

  /**
   * \brief Garbage collector exception
   *
   * This exception is thrown when a wrong size has been defined
   * during an allocation. Typically, when 0 is given.
   */
  DefineException(InvalidSize, "A wrong size has been specified for allocation");

  /**
   * \brief Garbage collector exception
   *
   * This exception is thrown when a wrong set of flags has been defined
   * during an allocation. Typically, when you ask for both zeroed & marked memory.
   */
  DefineException(InvalidFlags, "A wrong set of flags has been specified for allocation");

  /**
   * \brief Garbage collector exception
   *
   * This exception is thrown when you ask new memory block but that memory block
   * would make the garbage collector go beyond defined quotas.
   */
  DefineException(NotEnoughSpace, "Memory allocation quota has been reached");

  /**
   * \brief Garbage collector exception
   *
   * This exception is thrown when the garbage collector needs to allocate memory
   * but the system refuses the allocation. You shouldn't ignore such exception.
   */
  DefineException(NoMemory, "There is no memory left on the system");

  /**
   * \brief Garbage collector exception
   *
   * This exception is thrown when the garbage collector detects corruption
   * in its internal structures and/or when it detects its internal data
   * are not consistent anymore. You MUSTN'T ignore such exception.
   * \internal
   * This is also the exception thrown by a falling garbage collector assert (GCAssert)
   */
  DefineException(ListCorrupted, "Garbage collector internal structures are corrupted");

  /**
   * \brief Garbage collector exception
   *
   * This exception is thrown when the garbage collector is given an address
   * it does not know anything about. This can be thrown in case of a double-free.
   */
  DefineException(InvalidAddress, "Given address is not known by garbage collector");

  /**
   * \brief Garbage collector exception
   *
   * This exception is thrown when the garbage collector is asked to deal with memory
   * whereas it is empty (ie, nothing allocated yet).
   */
  DefineException(TooMuchSpace, "There is nothing allocated");

  /**
   * \brief Garbage collector exception
   *
   * This exception is thrown when the garbage collector is asked to release
   * a tagged block, but the given freeing that does not match the tag given for
   * allocation.
   */
  DefineException(InvalidTag, "The given tag does not match block tag");

  /**
   * \brief Garbage collector exception
   *
   * This exception is thrown when the garbage collector is asked to free a memory block
   * which is lock by thread owner. And the calling thread is not the block owner.
   */
  DefineException(WrongFreer, "The thread trying to free the block is not the owner");

  /**
   * \brief Garbage collector exception
   *
   * This exception is thrown when the garbage collector detects that a memory block is
   * corrupted (written beyond and/or before). You shouldn't ignore such exception.
   */
  DefineException(MemoryBlockCorrupted, "The required memory block seems to be corrupted. Check you program!");
  /**
   * \brief Garbage collector exception
   *
   * This exception is thrown when the garbage collector encounters an internal error that
   * cannot be recovered. You cannot ignore such exception.
   */
  DefineException(InternalError, "The garbage collector encountered a non-recoverable error and will likely not work!");

  /**
   * \brief Main garbage collector class.
   *
   * This garbage collector is a powerful one relying on references
   * to define whether a block should be freed.
   * It comes with several and important features:
   *
   * - It can allocate you blocks from both paged and non-paged memory
   *
   * - It checks memory for corruption and lets you know once it detects corruption
   *
   * - It checks for double-free
   *
   * - It is using tags to let you debug memory more easily
   *
   * - It helps you validating memory you use
   *
   * - It provides support for allocating temporary blocks
   *
   * - It supports memory usage limitation
   * \warning Beware, any method in this class is lickely to throw
   * a ListCorrupted or a MemoryBlockCorrupted exception
   * whenever it is needed.
   */
  class GarbageCollector
  {
    private:
      /**
       * \brief Internal structure used by garbage collector
       * \internal
       * Structure used by garbage collector to store
       * a memory block address and information
       * it gives to the user.
       * It is used as a linked list for both free space
       * and allocated space 
       */
      struct MemoryBlock
      {
        void * pBlock; /**< Address to the allocated block */
        size_t uBlockSize; /**< Size requested by the user (vs really allocated). It is 32bits aligned */
        bool bBlockNonPageable; /**< Set to true if the block must stay in RAM */
        bool bBlockWeak; /**< Set to true if the block is a weak block */
        unsigned long ulBlockTag; /**< Contains tag if user specified any */
        unsigned int uiBlockReferences; /**< Number of references pointing to the block */
        unsigned long ulBlockOwner; /**< ID of the thread owner. 0 if lock is unused */
        bool bBlockFreed; /**< Set to true if block is freed */
        bool bBlockLookaside; /**< Set to true if block is lookaside */
        void * pCallingAddress; /**< Address in binary where the allocation has been requested */
        struct MemoryBlock * pNextBlock; /**< Pointer to the next block */
        struct MemoryBlock * pPrevBlock; /**< Pointer to the previous block */
      };

      /**
       * \internal
       * Dynamic linked list storing all allocated addresses
       */
      MemoryBlock * pmbAllocated;
      /**
       * \internal
       * Dynamic linked list storing all freed addresses
       */
      MemoryBlock * pmbFreed;
      /**
       * \internal
       * Size of the internal dynamic lists.
       * Note that pmbFreed might be bigger, but pmbAllocated never.
       */
      size_t uListsMaxSize;
      /**
       * \internal
       * Number of entries in allocated list
       */
      unsigned int uiAllocatedCount;
      /**
       * \internal
       * Number of entries in freed list
       */
      unsigned int uiFreedCount;
      /**
       * \internal
       * Number of weak entries in pmbAllocated
       * It's here for performance reasons
       */
      unsigned int uiWeakCount;
      /**
       * \internal
       * Number of lookaside entries in pmbFreed
       * It's here for performance reasons
       */
      unsigned int uiLookasideCount;
      /**
       * \internal
       * Linked lists lock. To permit threaded use of the garbage collector.
       */
      Mutex mListsLock;
      /**
       * \internal
       * Counts number of bytes allocated by garbage collector.
       * To keep count realistic, must succeed aren't counted.
       */
      unsigned long ulTotalAllocated;
      /**
       * \internal
       * Limit for memory allocation in bytes. It is counted in bytes.
       */
      unsigned long ulMaxBytes;

      /**
       * \internal
       * Pointer to the system malloc syscall
       */
      void * (* pSystemMalloc)(size_t);
      /**
       * \internal
       * Pointer to the system malloc syscall
       */
      void (* pSystemFree)(void *);

      /**
       * \internal
       * Garbage Collector constructor.
       *
       * It just allocates internal linked lists and initiate them. It also
       * sets predefined settings.
       * @return Nothing
       */
      GarbageCollector() throw(InternalError);
      /**
       * \internal
       * Garbage Collector copy constructor.
       *
       * It just allocates internal linked lists and initiate them
       * by copying the other garbage collector. It also imports settings.
       * @return Nothing
       */
      GarbageCollector(const GarbageCollector& inGC) throw();

      /**
       * \internal
       * It allocates a new block of Size usable bytes. Block it returns is signed
       * on first 4 bytes and last 4 bytes (extra space) to detect memory corruption.
       * @param Size Size of usable space of the block to allocate. It has to be 32 bits aligned.
       * @param NonPageable Defines whether memory must be allocated in a way it stays in RAM or if
       * it may be paged to disk.
       * @param ZeroBlock If set to true, the returned block will be fill in with zeros. Otherwise
       * memory will be kept uninitialized.
       * @param NotExtended Optional parameter which defines whether allocated memory must be marked
       * to check corruption. Faulty, it is off. Note that if that parameter is set to true,
       * size may not be 32bits aligned.
       * @param MustSucceed Optional parameter which defines whether allocated memory is done for
       * MUST_SUCCEED allocation. Faulty it is off. Note that is that parameter is set to true,
       * NonPageable parameter is ignored.
       * @return Address of the allocated block
       * \warning For signature reason, when calling that function, Size MUST be 32bits aligned!
       * \warning Beware when a block is asked to be non-pageable and the lock fails, the
       * function returns the address of the allocated block made odd!
       */
      void * AllocateBlock(size_t Size, bool NonPageable, bool ZeroBlock, bool NotExtended = false, bool MustSucceed = false) throw(ListCorrupted);
      /**
       * \internal
       * This is really the allocating function.
       * It should always be called from wrappers not to mess up with stack
       * Check AllocateWithTag for complete documentation.
       * @param Size Size of the memory you want to use
       * @param Flags Options that will change the way function will allocate memory
       * @param Tag Four letters that will be associated to memory block
       * @return Memory block address in case of success, 0 otherwise
       * @see AllocateWithTag()
       * \warning To respect caller hierarchy, it's highly recommended to use it in any
       * allocating function exposed to the user.
       * \warning This is also for this reason that this function has not to be inlined
       */
      void * AllocateWithTagInt(size_t Size, unsigned int Flags, unsigned long Tag)
        throw(InvalidSize, InvalidFlags, ListCorrupted, MemoryBlockCorrupted, NoMemory, NotEnoughSpace)
        __attribute__((noinline));
      /**
       * \internal
       * It looks through the linked lists in order to find the real address of the
       * user given address. In case it finds it, it will return its corresponding
       * MemoryBlock entry. In case it does not find it, it will throw an exception and
       * return 0.
       * With MustBeValid enabled, it will also check whether address is in use.
       * In case it is enabled and address is not in use, it will throw an exception.
       * This function uses the following exceptions: TooMuchSpace, InvalidAddress.
       * @param UserAddress Address the user is aware of. It is not the real memory block address.
       * @param MustBeValid Define whether we return normally if the address is not in use.
       * @return Entry of the block in one of the linked lists, or 0 if unfound.
       * \warning Lists lock must have been acquired before calling that method.
       */
      MemoryBlock * FindBlock(const void * UserAddress, bool MustBeValid) const throw(TooMuchSpace, InvalidAddress, ListCorrupted);
      /**
       * \internal
       * Free a block previously allocated using AllocateBlock().
       * @param BlockAddress Address of the block to free.
       * @param NonPaged Set to true if memory was to be non paged to disk.
       * @param BlockSize It is block size
       * @param IsNotExtended Optional parameter. Each memory block that GC protects against corruption is extended
       * @return Nothing
       */
      void FreeBlock(void * BlockAddress, bool NonPaged, size_t BlockSize, bool IsNotExtended = false) throw(ListCorrupted);
      /**
       * \internal
       * This function returns the thread ID of the calling thread.
       * @return Thread ID (casted to be platform independant)
       */
      unsigned long GetThreadID() const throw();
      /**
       * \internal
       * This function links one entry in the given list.
       * The insertion is done at head.
       * @param ListHead Head of the list to change
       * @param Entry Entry to link
       * \warning Lists lock must have been acquired before calling that method.
       */
      void LinkEntry(MemoryBlock ** ListHead, MemoryBlock * Entry) throw();
      /**
       * \internal
       * This function tries to lock a block in memory.
       * It means that the block cannot be paged on the disk.
       * @param BlockAddress Address of the block to lock
       * @param BlockSize Size of memory to lock
       * @param IsNotExtended Optional, if to false extended size will be used
       * @return True if lock succeed, false otherwise
       */
      bool LockBlock(void * BlockAddress, size_t BlockSize, bool IsNotExtended = false) throw(ListCorrupted);
      /**
       * \internal
       * This function unlinks one entry in the given list.
       * It can update head, if required.
       * @param ListHead Head of the list entry belongs to
       * @param Entry Entry to unlink
       * \warning Lists lock must have been acquired before calling that method.
       */
      void UnlinkEntry(MemoryBlock ** ListHead, MemoryBlock * Entry) throw();
      /**
       * \internal
       * This function tries to unlock a previously locked block in memory.
       * @param BlockAddress Address of the block to unlock
       * @param BlockSize Size of memory to unlock
       * @param IsNotExtended Optional, if to false extended size will be used
       * @return True if unlock succeed, false otherwise
       */
      bool UnlockBlock(void * BlockAddress, size_t BlockSize, bool IsNotExtended = false) throw(ListCorrupted);
      /**
       * \internal
       * Check whether the given block is marked, and if marks are still valid.
       * @param BlockAddress Addess of the block to check
       * @param Size Total size of the block
       * @return True if the block is valid, false otherwise
       */
      bool ValidateBlock(const void * BlockAddress, size_t Size) const throw(ListCorrupted);

      /**
       * \internal
       * Affectation operator.
       * It copies garbage collector to the new place and releases the old one. That means
       * that all memory allocated by old garbage collector will be released.
       * Furthermore, before any operation on old garbage collector, it is checked
       * for its integrity. If the check fails, an exception is thrown, and nothing
       * is changed.
       * This function uses the following exceptions: ListCorrupted, MemoryBlockCorrupted.
       * @param inGC the garbage collector that will be affected
       * @return A reference to the filled in garbage collector
       * \warning This should never be used. It is here just for
       * sanity purposes.
       */
      GarbageCollector& operator=(const GarbageCollector &inGC) throw(ListCorrupted, MemoryBlockCorrupted);

    public:
      /**
       * Gabage Collector destructor.
       *
       * It goes through the internal structures, finds still valid entries and
       * releases them. Then, it frees internal structures.
       * @return Nothing
       */
      ~GarbageCollector();

      /**
       * It allocates a new memory block to the user.
       * @param Size of the block to allocate
       * @param Flags Options that will change the way function will allocate memory 
       * @return Memory block address in case of success, 0 otherwise
       * @see AllocateWithTag()
       * \internal
       * It just realises a call to AllocateWithTag() using 0 as tag.
       */
      void * Allocate(size_t Size, unsigned int Flags)
        throw(InvalidSize, InvalidFlags, ListCorrupted, MemoryBlockCorrupted, NoMemory, NotEnoughSpace);
      /**
       * It allocates a new memory block to the user.
       * The following options are possible, using flags:
       *
       * - PAGED_BLOCK: means that the block can be paged (faulty).
       * It is the equivalent of a malloc call.
       *
       * - NON_PAGED_BLOCK: means that the block will never be paged.
       * Note that making a block non-pageable is an operation that can
       * fail. In such situation, the allocation will be refused, and 0
       * address will be returned (and NoMemory thrown if RAISE_ON_FAILURE flag
       * is set).
       * Note that in such case you can force for allocation success using
       * MUST_SUCCEED flag. Then, the garbage collector will return the
       * block, even if it is pageable. That possibility should be used
       * carefully due to potential side effects of MUST_SUCCEED flag.
       *
       * - RAISE_ON_FAILURE: means that instead of returning 0 on failure, an
       * exception will be thrown.
       *
       * - MUST_SUCCEED: means that garbage collector will do everything
       * it can to find you memory. Even the worst things ever. Which means
       * that the returned memory address may not be saved by the garbage
       * collector nor handled. In other terms, the returned block may not
       * be protected against corruption or double free, it would also
       * be leaked in case you do not properly free it. Of course, in such
       * situation, if you asked for a non-paged block using NON_PAGED_BLOCK flag,
       * this setting will be simply ignored. Obviously, if you also set the
       * OWNER_LOCK flag, it will be ignored as well. Same for CACHING_BLOCK flag.
       * ZEROED_BLOCK and MARKED_BLOCK flags are never ignored.
       * When you set the MUST_SUCCEED flag on, you also set the flag RAISE_ON_FAILURE
       * on. So, be prepared to catch exception in case allocation failed.
       * Once the block is returned, you have absolutely no way to know
       * whether that block was properly linked in the garbage collector.
       * Then it is hardly recommanded that you never reallocate such block.
       * Furthermore, when freeing such block, make sure you are ready to catch
       * any exception Free()/FreeWithTag() may throw you. If they are
       * throwing InvalidAddress, TooMuchSpace, it is likely that your block
       * is not linked in the garbage collector. Consider freeing it using
       * delete operator instead.
       * Finally, you should NEVER use that flag unless you know exactly
       * what you do, why you do it, and because you have lost the will
       * to live.
       * Use that flag only for critical memory blocks that you
       * absolutely need.
       * Note that if garbage collector isn't full, using that flag might help on
       * other allocations. See the other documented flags.
       *
       * - OWNER_LOCK: means that the garbage collector will get the thread
       * ID of the thread requesting the allocation and will store it. Only that
       * thread will be able to free the memory block. Any other thread trying
       * to free the block will receive an exception. On the other hand, everyone
       * is free to access the block.
       *
       * - ZEROED_BLOCK: means that the garbage collector will fill in the block
       * with zeros before it returns it. It is the equivalent of a calloc call.
       *
       * - MARKED_BLOCK: means that the garbage collector will mark memory
       * using defined pattern before it returns it. You can use that flag for
       * debug purposes (spotting use of uninit blocks). If the memory you
       * want to read returns 0xbaaadbed you have to initialize it first.
       * But, marking process is a quite slow process, you should only use it
       * for debug purposes and not for releases.
       *
       * - CACHING_BLOCK: means that the garbage collector will invalidate and free
       * that block whenever it needs memory. This means you can never predicate
       * before use whether your address is still valid. Consider using the function
       * IsAddressValid() to ensure it is valid before use. As lifetime of such
       * objects cannot be known, use them to cache data. When address is still valid
       * and you do not need such block any more, just free it as any other block.
       * If you do not release such blocks before quitting, garbage collector will not
       * consider them as leakage. Then, do not be surprised if you got 0 bytes memory
       * leaked while quitting whereas you had allocated much memory using CACHING_BLOCK.
       * Those blocks are also checked against corruption and double-free.
       * Those blocks are likely to be freed when you call Allocate() and AllocateWithTag().
       * The garbage collector may refuse you the allocation of a CACHING_BLOCK if it is
       * low in memory but not full (block lifetime would be too short).
       * Note that in such case you can force for allocation success using
       * MUST_SUCCEED flag. Then, the garbage collector will return the
       * block, and consider it as caching block. That possibility should be used
       * carefully due to potential side effects of MUST_SUCCEED flag.
       *
       * - LOOKASIDE_BLOCK: means that the garbage collector will keep the block in
       * memory even after you called for a free. The main idea is to use that flag
       * for small blocks you keep allocating and freeing. That way, allocations
       * and freeings go faster.
       * Note that security issues may raise. If block is not free, it stays available
       * and address is not invalidated. Also, make you sure you do not reuse this
       * address after free.
       * Note that even if you ask for a fixed size, due to the way lookaside blocks work
       * and to prevent memory eating (too much) the returned block might be really bigger
       * than what you expected to get. Never ever go beyond the size you asked as you cannot
       * know where the end is.
       * Note that each time such block is returned, it is already zeroed. Then, you
       * cannot use that allocation flag with MARKED_BLOCK flag.
       * Note that this flag cannot be used with CACHING_BLOCK flag (even with MUST_SUCCEED
       * flag yet).
       * Be really careful when using that flag with MUST_SUCCEED flag. In case you are hitting
       * a quota while asking for memory, garbage collector may unlink an existing block
       * and forget about it to be able to return it.
       * Also be really careful if you reallocate such block. The property will be kept. Keep it
       * in mind while making a lookaside block growth. On the other hand, if you do not need a
       * lookaside block any more, just reallocate it with size 1.
       *
       * Tag can be used to mark memory block in memory and be
       * able to display it properly. Define tag by using four characters.
       * If you wish not to use tags, give it value 0, or call Allocate().
       * Note that if you provide a tag to allocate a memory block, you have to
       * provide the same tag for releasing it.
       * Also note that depending on the memory size you are requesting
       * garbage collector may give you a bit more memory since it is
       * 32 bits aligned block size. Use only what you asked to prevent
       * any memory corruption.
       * When RAISE_ON_FAILURE flag is set, this function uses the
       * following exceptions: InvalidSize, InvalidFlags, NotEnoughSpace, NoMemory.
       * @param Size Size of the memory you want to use
       * @param Flags Options that will change the way function will allocate memory
       * @param Tag Four letters that will be associated to memory block
       * @return Memory block address in case of success, 0 otherwise
       */
      void * AllocateWithTag(size_t Size, unsigned int Flags, unsigned long Tag)
        throw(InvalidSize, InvalidFlags, ListCorrupted, MemoryBlockCorrupted, NoMemory, NotEnoughSpace);
      /**
       * This function is the most complete check against corruption
       * that can be run on the garbage collector. It will check the whole
       * internal linked lists for corruption including corruption on
       * the linked lists themselves (not only on allocated blocks).
       * Even if that function may be useful to know whether your programs
       * are correct, use it carefully as it may drastically slow down
       * your programs.
       * This functions uses the following exceptions: ListCorrupted,
       * MemoryBlockCorrupted
       * @return Nothing
       */
      void CheckForCorruption() const throw(ListCorrupted, MemoryBlockCorrupted);
      /**
       * Informs garbage collector that one less object is referencing
       * the given address.
       * If the rerefence count finally reach 0, the address will be freed
       * @param Address Memory address you want to dereference
       * @return Nothing
       * \warning In case freeing fails an exception will be thrown.
       * \internal
       * For freeing, it realises a call to Free().
       */
      void Dereference(void * Address)
        throw(TooMuchSpace, InvalidAddress, ListCorrupted, InvalidTag, WrongFreer, MemoryBlockCorrupted);
      /**
       * It frees the complete block given at the address.
       * @param Address Memory address you want to free
       * @return Nothing
       * @see FreeWithTag()
       * \warning In case freeing fails an exception will be thrown.
       * \internal
       * It just realises a call to FreeWithTag() using 0 as tag.
       */
      void Free(void * Address)
        throw(TooMuchSpace, InvalidAddress, ListCorrupted, InvalidTag, WrongFreer, MemoryBlockCorrupted);
      /**
       * It frees the complete block given at the address.
       * This function does not check if they are still references
       * on the block to free.
       *
       * If you want to free a tagged block, you need to provide
       * the appropriate tag.
       *
       * Note that 0 tag is matching every tag.
       *
       * Note that to ensure double-free detection, garbage collector
       * keeps a fingerprint of the freed address. Lifetime of that
       * figerprint cannot be predicted.
       *
       * This functions uses the following exceptions: TooMuchSpace, InvalidAddress,
       * AddressUnused, InvalidTag, WrongOwner, MemoryBlockCorrupted.
       * @param Address Memory address you want to free
       * @param Tag Tag used for allocating memory block. Use 0 if none.
       * @return Nothing
       * \warning In case freeing fails an exception will be thrown.
       */
      void FreeWithTag(void * Address, unsigned long Tag)
        throw(TooMuchSpace, InvalidAddress, ListCorrupted, InvalidTag, WrongFreer, MemoryBlockCorrupted);
      /**
       * This function just returns the total allocated memory
       * by the garbage collector. As it is a counter maintained by
       * the garbage collector itself, it requires no calculation
       * each time you call this function.
       * Note that the return size will not match the total memory
       * size your programme allocated. This counter also takes into
       * account memory it uses internally.
       * @return Total allocated memory in bytes.
       */
      unsigned long GetTotalAllocated() const throw();
      /**
       * It checks whether the given address is correct.
       * If IsInBlock is defined, then the address can point
       * anywhere in an allocated block. Otherwise, address
       * has to be the begin of the block.
       * Note that, due to memory alignement used by garbage collector,
       * that function may return that an address is valid while
       * it is overruning the size the user actually demanded.
       * Moreover the function just checks whether the address is valid.
       * It doesn't check for valid pointed block, ie, if there is some
       * corruption, it will still return true.
       * @param Address Memory address to check
       * @param IsInBlock Set it to true if address can point anywhere in a block
       * @return True if the address is valid
       */
      bool IsAddressValid(const void * Address, bool IsInBlock) const throw();
      /**
       * It reallocates a block of memory to the new size
       * @param Address Memory address to reallocate
       * @param Size New size of the memory block
       * @return The address of the reallocated block, 0 if it failed
       * @see ReallocateWithTag()
       * \warning In case of pure allocation/freeing, it may throw exceptions
       * \internal. See AllocateWithTag() and FreeWithTag() for more information
       * about those exceptions.
       * It just realises a call to ReallocateWithTag() using 0 as tag.
       */
      void * Reallocate(void * Address, size_t Size)
        throw (InvalidSize, InvalidFlags, ListCorrupted, MemoryBlockCorrupted, NoMemory, NotEnoughSpace, TooMuchSpace, InvalidAddress, InvalidTag, WrongFreer);
      /**
       * It reallocates a block of memory to the new size. It does it
       * in two times, it first allocates a new block and copy old data there
       * and then free old block. Which means you cannot ignore function return;
       * your block will always be relocated.
       * This function may behave differently depending on your entry. If you provide
       * no address, it will allocate a new block. If you provide no size, it will free
       * given address. If you provide an already freed block, it will allocate a new
       * block.
       *
       * Note that function checks for memory corruption in the block and will always
       * fail to reallocate in case it detects corruption.
       *
       * Note that if you allocated primary block using a tag, you will have to reallocate
       * providing that tag. If you did not use tag, use 0 as tag.
       *
       * Note that if you asked for zeroed or marked memory for primary allocation, that
       * demand is not stored. Which means that the returned memory here is just initialized
       * with primary data. No more management is done.
       *
       * Note that if you use that function on a caching block, the behaviour of the function
       * might be unpredictable. If the block was already freed, the function will fail or
       * reallocate the caching block. If it was not freed, then it is normally reallocated.
       * In case it was freed and then reallocated, block will remain caching block.
       *
       * Note that if reallocation failed, the function is returning 0. It does not mean that
       * the block you passed for reallocation has been freed or is invalid. It is still valid
       * and usuable.
       *
       * Note that this function also checks for quota (defined with SetAllocationsLimit() and
       * SetMemoryLimit()) and may refuse reallocation just if it is about to hit one of quota.
       *
       * Also note that this function, as AllocateWithTag() provides 32bits aligned blocks.
       * which means you can get a block a bit bigger than what you asked. Never use more
       * than what you asked.
       *
       * Finaly, note that it exists a case where your memory block will not be relocated
       * nor reallocated. When you ask a small grow up in a block that has been aligned and
       * it still fits. In such case, garbage collector just returns your block.
       *
       * This function uses the following exceptions (in case of pure allocation/freeing):
       * InvalidSize, InvalidFlags, NotEnoughSpace, NoMemory, TooMuchSpace, InvalidAddress,
       * AddressUnused, InvalidTag, WrongOwner, MemoryBlockCorrupted
       * @param Address Memory address to reallocate
       * @param Size New size of the memory block
       * @param Tag Tag used for primary allocation
       * @return The address of the reallocated block, 0 if it failed
       * \warning In case of pure allocation/freeing, it may throw exceptions
       */
      void * ReallocateWithTag(void * Address, size_t Size, unsigned long Tag)
        throw (InvalidSize, InvalidFlags, ListCorrupted, MemoryBlockCorrupted, NoMemory, NotEnoughSpace, TooMuchSpace, InvalidAddress, InvalidTag, WrongFreer);
      /**
       * Informs garbage collector that one more object is referencing
       * the given address.
       * @param Address Memory address you want to reference
       * @return Nothing
       */
      void Reference(void * Address) throw(ListCorrupted);
      /**
       * Define how many blocks the garbage collector may give you at a time.
       * If you ask for more, then, it will refuse any allocation.
       * If you want no limit, use LIMIT_UNLIMITED constant.
       * Note that 0 is not a valid value, and will always lead to a failure.
       * @param MaxSize Number of allocations, if not set, it is faulty to INIT_LISTS_SIZE
       * @return Nothing True if the limit could be set, false otherwise
       */
      bool SetAllocationsLimit(size_t MaxSize = INIT_LISTS_SIZE) throw();
      /**
       * Define how much memory the garbage collector may use at a time.
       * If you ask for more, then, it will refuse any allocation.
       * If you want no limit, use LIMIT_UNLIMITED constant.
       * Note that 0 is not a valid value, and will always lead to a failure.
       * Note that during a garbage collector method call, it may consume more
       * than that quota. But once call is over, the quota is matched, whatever
       * happened internally.
       * @param MaxSize Maximum bytes, if not set, it is faulty to INIT_MEM_SIZE
       * @return True if the limit could be set, false otherwise
       */
      bool SetMemoryLimit(unsigned long MaxSize = INIT_MEM_SIZE) throw();

      friend GarbageCollector& GetInstance() throw(InternalError);

      friend void * ::calloc(size_t nmemb, size_t size) throw();
      friend void * ::malloc(size_t size) throw();
      friend void * ::operator new(std::size_t size) throw (std::bad_alloc);
      friend void * ::operator new[](std::size_t size) throw (std::bad_alloc);
      friend void * ::operator new(std::size_t size, const std::nothrow_t&) throw();
      friend void * ::operator new[](std::size_t size, const std::nothrow_t&) throw();
  };

  /**
   * Returns the running instance of the garbage collector.
   * This ensures that only one instance of the garbe collector
   * exists.
   * @return Garbage collector instance
   */
  GarbageCollector& GetInstance() throw(gc::InternalError);
}

/**
 * Ancestor.
 * Allocate new memory block that can contain an array of nmemb.
 * Block will be initialised with zeros before being returned.
 * Note that compared to libc calloc, this function allocates blocks
 * linked in the garbage collector.
 * @param nmemb Number of elements in the array.
 * @param size Size of one array element.
 * @return Allocated block address, or 0 in case of a failure
 * \internal It is just a simple wrapper to Allocate() function
 */
extern "C" void * calloc(size_t nmemb, size_t size) throw();
/**
 * Ancestor.
 * Releases pointer.
 * Note that you can only give block addresses that have been allocated
 * by any of the function of this namespace.
 * @param ptr pointer to release.
 * @return Nothing
 * \internal It is just a simple wrapper to Free() function
 */
extern "C" void free(void * ptr) throw();
/**
 * Ancestor.
 * Allocate new memory block size big.
 * Note that compared to libc malloc, this function allocates blocks
 * linked in the garbage collector.
 * @param size Size of the memory block to allocate.
 * @return Allocated block address, or 0 in case of a failure
 * \internal It is just a simple wrapper to Allocate() function
 */
extern "C" void * malloc(size_t size) throw();
/**
 * Ancestor.
 * Used to reallocate a previously allocated block with new size.
 * If the size is 0, then, the block will be freed.
 * If the address is null, then a new block is allocated.
 * Note that you can only give block addresses that have been allocated
 * by any of the function of this namespace.
 * Note that contrary of "real" realloc function, most of the time, here,
 * ptr will be relocated, so you cannot ignore function return.
 * @param ptr Address of the block to realloc.
 * @param size New size of the block.
 * @return Reallocated block address, or 0 in case of a failure
 * \warning Do not fall into common mistake. In case of reallocation
 * failure (ie, return being 0), previous block is kept. Which means
 * that pointer you gave with ptr is STILL VALID.
 * \internal It is just a simple wrapper to Reallocate() function
 */
extern "C" void * realloc(void * ptr, size_t size) throw();

/**
 * Overload for C++ delete operator.
 * Use it to release any memory address the garbage collector
 * gave you (any successful call to new/Allocate/AllocateWithTag).
 * @param ptr Address to release.
 * @return Nothing
 * \internal It is just a simple wrapper to Free() function
 */
void operator delete(void * ptr) throw();
/**
 * Overload for C++ delete operator.
 * Use it to release any memory address the garbage collector
 * gave you (any successful call to new/Allocate/AllocateWithTag).
 * @param ptr Address to release.
 * @return Nothing
 * \internal It is just a simple wrapper to Free() function
 */
void operator delete[](void * ptr) throw();
/**
 * Overload for C++ delete operator.
 * Use it to release any memory address the garbage collector
 * gave you (any successful call to new/Allocate/AllocateWithTag).
 * @param ptr Address to release.
 * @return Nothing
 * \internal It is just a simple wrapper to Free() function
 */
void operator delete(void * ptr, const std::nothrow_t&) throw();
/**
 * Overload for C++ delete operator.
 * Use it to release any memory address the garbage collector
 * gave you (any successful call to new/Allocate/AllocateWithTag).
 * @param ptr Address to release.
 * @return Nothing
 * \internal It is just a simple wrapper to Free() function
 */
void operator delete[](void * ptr, const std::nothrow_t&) throw();
/**
 * Overload for C++ new operator. All new calls you will
 * do will be handled by garbage collector, to ensure
 * a proper memory management.
 * @param size Size of the object to allocate.
 * @return Address of the allocated objected
 * \internal It is just a simple wrapper to Allocate() function
 */
void * operator new(std::size_t size) throw (std::bad_alloc);
/**
 * Overload for C++ new operator. All new calls you will
 * do will be handled by garbage collector, to ensure
 * a proper memory management.
 * @param size Size of the object to allocate.
 * @return Address of the allocated objected
 * \internal It is just a simple wrapper to Allocate() function
 */
void * operator new[](std::size_t size) throw (std::bad_alloc);
/**
 * Overload for C++ new operator. All new calls you will
 * do will be handled by garbage collector, to ensure
 * a proper memory management.
 * This overload will not throw any exception and you
 * have to check returned address.
 * @param size Size of the object to allocate.
 * @return Address of the allocated objected or 0
 * \internal It is just a simple wrapper to Allocate() function
 */
void * operator new(std::size_t size, const std::nothrow_t&) throw();
/**
 * Overload for C++ new operator. All new calls you will
 * do will be handled by garbage collector, to ensure
 * a proper memory management.
 * This overload will not throw any exception and you
 * have to check returned address.
 * @param size Size of the object to allocate.
 * @return Address of the allocated objected or 0
 * \internal It is just a simple wrapper to Allocate() function
 */
void * operator new[](std::size_t size, const std::nothrow_t&) throw();

#endif

