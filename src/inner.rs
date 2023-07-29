use std::cell::Cell;
use std::fs::File;
use std::mem::ManuallyDrop;
use std::os::unix::io::{FromRawFd, RawFd};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{io, ptr};

use crate::advice::Advice;

pub struct MmapInner {
    ptr: Cell<*mut libc::c_void>,
    len: Cell<usize>,
}

impl MmapInner {
    /// Creates a new `MmapInner`.
    ///
    /// This is a thin wrapper around the `mmap` sytem call.
    fn new(
        len: usize,
        prot: libc::c_int,
        flags: libc::c_int,
        file: RawFd,
        offset: usize,
    ) -> io::Result<MmapInner> {
        let alignment = offset % page_size();
        let aligned_offset = offset - alignment;
        let aligned_len = len + alignment;

        // `libc::mmap` does not support zero-size mappings. POSIX defines:
        //
        // https://pubs.opengroup.org/onlinepubs/9699919799/functions/mmap.html
        // > If `len` is zero, `mmap()` shall fail and no mapping shall be established.
        //
        // So if we would create such a mapping, crate a one-byte mapping instead:
        let aligned_len = aligned_len.max(1);

        // Note that in that case `MmapInner::len` is still set to zero,
        // and `Mmap` will still dereferences to an empty slice.
        //
        // If this mapping is backed by an empty file, we create a mapping larger than the file.
        // This is unusual but well-defined. On the same man page, POSIX further defines:
        //
        // > The `mmap()` function can be used to map a region of memory that is larger
        // > than the current size of the object.
        //
        // (The object here is the file.)
        //
        // > Memory access within the mapping but beyond the current end of the underlying
        // > objects may result in SIGBUS signals being sent to the process. The reason for this
        // > is that the size of the object can be manipulated by other processes and can change
        // > at any moment. The implementation should tell the application that a memory reference
        // > is outside the object where this can be detected; otherwise, written data may be lost
        // > and read data may not reflect actual data in the object.
        //
        // Because `MmapInner::len` is not incremented, this increment of `aligned_len`
        // will not allow accesses past the end of the file and will not cause SIGBUS.
        //
        // (SIGBUS is still possible by mapping a non-empty file and then truncating it
        // to a shorter size, but that is unrelated to this handling of empty files.)

        unsafe {
            let ptr = libc::mmap(
                ptr::null_mut(),
                aligned_len as libc::size_t,
                prot,
                flags,
                file,
                aligned_offset as libc::off_t,
            );

            if ptr == libc::MAP_FAILED {
                Err(io::Error::last_os_error())
            } else {
                Ok(MmapInner {
                    ptr: Cell::new(ptr.add(alignment)),
                    len: Cell::new(len),
                })
            }
        }
    }

    pub fn map_mut(len: usize, file: RawFd, offset: usize) -> io::Result<MmapInner> {
        MmapInner::new(
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            file,
            offset,
        )
    }

    // NOT THREAD SAFE:
    // This is unsafe because it is not thread safe and actually mutates self.
    // We do not expose this publicly.
    pub(crate) unsafe fn resize(&self, new_len: usize) -> io::Result<()> {
        let result_ptr = unsafe {
            libc::mremap(
                self.ptr.get(),
                self.len.get(),
                new_len,
                libc::MREMAP_MAYMOVE,
            )
        };

        if result_ptr == libc::MAP_FAILED {
            Err(io::Error::last_os_error())
        } else {
            // Interior Mutability
            self.ptr.replace(result_ptr);
            self.len.replace(new_len);

            // Make sure no future actions happen with the old ptr & len
            std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);

            Ok(())
        }
    }

    pub fn flush(&self, offset: usize, len: usize) -> io::Result<()> {
        let alignment = (self.ptr.get() as usize + offset) % page_size();
        let offset = offset as isize - alignment as isize;
        let len = len + alignment;
        let result = unsafe {
            libc::msync(
                self.ptr.get().offset(offset),
                len as libc::size_t,
                libc::MS_SYNC,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub fn flush_async(&self, offset: usize, len: usize) -> io::Result<()> {
        let alignment = (self.ptr.get() as usize + offset) % page_size();
        let offset = offset as isize - alignment as isize;
        let len = len + alignment;
        let result = unsafe {
            libc::msync(
                self.ptr.get().offset(offset),
                len as libc::size_t,
                libc::MS_ASYNC,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    #[inline]
    pub fn ptr(&self) -> *const u8 {
        self.ptr.get() as *const u8
    }

    #[inline]
    pub fn mut_ptr(&mut self) -> *mut u8 {
        self.ptr.get() as *mut u8
    }

    #[inline]
    // this is used to write in a thread-safe way by code internal to this crate only
    pub(crate) unsafe fn unsafe_mut_ptr(&self) -> *mut u8 {
        self.ptr.get() as *mut u8
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len.get()
    }

    pub fn advise(&self, advice: Advice, offset: usize, len: usize) -> io::Result<()> {
        let alignment = (self.ptr.get() as usize + offset) % page_size();
        let offset = offset as isize - alignment as isize;
        let len = len + alignment;
        unsafe {
            if libc::madvise(self.ptr.get().offset(offset), len, advice as i32) != 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    pub fn lock(&self) -> io::Result<()> {
        unsafe {
            if libc::mlock(self.ptr.get(), self.len.get()) != 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    pub fn unlock(&self) -> io::Result<()> {
        unsafe {
            if libc::munlock(self.ptr.get(), self.len.get()) != 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }
}

impl Drop for MmapInner {
    fn drop(&mut self) {
        let alignment = self.ptr.get() as usize % page_size();
        let len = self.len.get() + alignment;
        let len = len.max(1);
        // Any errors during unmapping/closing are ignored as the only way
        // to report them would be through panicking which is highly discouraged
        // in Drop impls, c.f. https://github.com/rust-lang/lang-team/issues/97
        unsafe {
            let ptr = self.ptr.get().offset(-(alignment as isize));
            libc::munmap(ptr, len as libc::size_t);
        }
    }
}

unsafe impl Sync for MmapInner {}
unsafe impl Send for MmapInner {}

fn page_size() -> usize {
    static PAGE_SIZE: AtomicUsize = AtomicUsize::new(0);

    match PAGE_SIZE.load(Ordering::Relaxed) {
        0 => {
            let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };

            PAGE_SIZE.store(page_size, Ordering::Relaxed);

            page_size
        }
        page_size => page_size,
    }
}

pub fn file_len(file: RawFd) -> io::Result<u64> {
    // SAFETY: We must not close the passed-in fd by dropping the File we create,
    // we ensure this by immediately wrapping it in a ManuallyDrop.
    unsafe {
        let file = ManuallyDrop::new(File::from_raw_fd(file));
        Ok(file.metadata()?.len())
    }
}
