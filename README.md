# mmap-append

This is a memory mapping crate.

It utilizes `memmap2` and provides a resizable append-only map with very low lock contention. An `RwLock<MmapMut>` from the `memmap2` crate works, but writers block readers and readers block writers. In our implementation, only writers block writers, or they block everything during a resize.

It uses an interior lock to prevent two different processes from appending at the same time, and a different interior lock to get exclusive access during the resize, which may change the virtual address of the map. The virtual address of the map changing should not matter to callers who access the memory via slices, and there can be no active borrowed slices when the resize happens due to the locking mechanism.
