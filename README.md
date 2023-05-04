# mmap-append

This is a memory mapping crate for unix only.

The `MmapAppend` is a memory map that is append-only. It uses an interior lock to prevent two different processes from appending at the same time.

It is also resizeable (via `libc::mremap`, unlike the `memmap` crate) and uses a different interior lock to get exclusive access during the resize, which may change the virtual address of the map.

This structure has less lock contention than an `RwLock<MmapMut>` has because writers do not block readers. The only time readers are blocked is while the map is being resized via a resize() call.
