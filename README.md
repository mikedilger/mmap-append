# mmap-append

This crate provides an append-only memory map with very low lock contention. A writer can be appending new data while multiple readers are reading the earlier data. This is better than using an `RwLock<MmapMut>` since in that case writers would block readers.

It is built on top of [memmap2](https://github.com/RazrFalcon/memmap2-rs).

It uses an interior lock to prevent two different processes from appending at the same time, and a different interior lock to get exclusive access during the resize, which may change the virtual address of the map. The virtual address of the map changing should not matter to callers who access the memory via slices, and there can be no active borrowed slices when the resize happens due to the locking mechanism.

NOTE: before 0.2.0 this crate was unix only, but that restriction no longer applies.
