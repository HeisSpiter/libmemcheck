libmemcheck
===========

libmemcheck is a library that you can dynamically hook to your application (before starting it) that will provide functionnalities such as:
 * Garbage collection
 * Memory overrun/underrun detection


If you use it as a memory manager in your application (not hooked then), it will provide memory features such as:
 * Lookaside memory
 * Memory locking in RAM

How to use it?
===========
Simply build it and execute your application with: <code>LD_PRELOAD=PATH/TO/libmemcheck.so ./your_application</code>
