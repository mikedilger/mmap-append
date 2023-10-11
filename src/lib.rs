pub use memmap2;
use memmap2::{Advice, MmapRaw};

use std::fmt;
use std::io::{self, Result};
use std::ops::Deref;
use std::os::unix::io::{AsRawFd, RawFd};
use std::slice;
use std::sync::{Mutex, RwLock};

/// A handle to an append-only memory mapped buffer.
///
/// Dereferencing this gives a `&[u8]` array of bytes which consists only of the
/// bytes previously appended, not the entire unused space.
///
/// There will be an area the size of a usize at the start of the file which is
/// used internally to record where the written content ends.
///
/// Only one writer may append at a time (the other writers will spin-wait). Readers are not
/// blocked while an append is taking place.
pub struct MmapAppend {
    // Only one writer may append at a time.
    append_lock: Mutex<()>,

    // Needed for remap workaround
    fd: RawFd,

    // This is the mmap. It has a usize at the beginning indicating where the end of the content lies
    // It is write locked only in the case of resizing, not in the case of appending.
    pub(crate) inner: RwLock<MmapRaw>,
}

#[cfg(target_os = "linux")]
fn remap(_fd: RawFd, inner: &mut MmapRaw, new_len: usize) -> Result<()> {
    unsafe { inner.remap(new_len, memmap2::RemapOptions::new().may_move(true)) }
}

#[cfg(not(target_os = "linux"))]
fn remap(fd: RawFd, inner: &mut MmapRaw, new_len: usize) -> Result<()> {
    inner.flush()?;
    let map = memmap2::MmapOptions::new().len(new_len).map_raw(fd)?;
    // Drop the old map after making a new map
    let _ = std::mem::replace(inner, map);
    Ok(())
}

pub const HEADER_SIZE: usize = std::mem::size_of::<usize>();

impl MmapAppend {
    /// Creates Mmaps the `file` returning an MmapAppend object. The entire file will be mapped.
    ///
    /// If `initialize` is true, it writes the initial end marker setting the end of the
    /// data to right after the end marker.
    ///
    /// There is no offset and it does not populate.
    ///
    /// ## Safety
    ///
    /// This is  `unsafe` because of the potential for *Undefined Behavior* (UB) using the map if the underlying
    /// file is subsequently modified, in or out of process. Applications must consider the risk and take appropriate
    /// precautions when using file-backed maps. Solutions such as file permissions, locks or process-private
    /// (e.g. unlinked) files exist but are platform specific and limited.
    pub unsafe fn new<T: MmapAsRawDesc>(file: T, initialize: bool) -> Result<MmapAppend> {
        let fd = file.as_raw_desc().0;
        // Will automatically look up the file length
        let map = MmapRaw::map_raw(fd)?;
        // File must be long enough for a usize 'end' record at the front
        if map.len() < HEADER_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "File not large enough.",
            ));
        }

        if initialize {
            // write the end value to the beginning
            let slice: &mut [u8] =
                unsafe { slice::from_raw_parts_mut(map.as_mut_ptr(), HEADER_SIZE) };
            slice[0..HEADER_SIZE].copy_from_slice(&HEADER_SIZE.to_le_bytes());
            map.flush_range(0, HEADER_SIZE)?;
        }

        Ok(MmapAppend {
            append_lock: Mutex::new(()),
            inner: RwLock::new(map),
            fd,
        })
    }

    /// Append data.
    ///
    /// This will return an error if there is not enough space.
    ///
    /// This may panic if the mutex is poisoned. If our code is not buggy, it will never happen.
    pub fn append<F>(&self, len: usize, writer: F) -> Result<usize>
    where
        F: FnOnce(&mut [u8]),
    {
        // Wait for and acquire the append lock
        let _guard = self.append_lock.lock().unwrap();

        // Read lock the map
        let inner = self.inner.read().unwrap();

        // Define a slice over the map
        let slice: &mut [u8] =
            unsafe { slice::from_raw_parts_mut(inner.as_mut_ptr(), inner.len()) };

        // Read the end marker
        let end = usize::from_le_bytes(slice[0..HEADER_SIZE].try_into().unwrap());

        // Check available space
        if end + len > inner.len() {
            return Err(io::Error::new(io::ErrorKind::Other, "Out of space"));
        }

        // Append
        writer(&mut slice[end..end + len]);

        // This is to make sure the end marker is not over-written until
        // strictly after the append happens
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);

        // Overwrite the end marker
        let newend = end + len;
        slice[0..HEADER_SIZE].copy_from_slice(&newend.to_le_bytes());

        Ok(end)
    }

    /// Resize the map. The caller is responsible for ensuring the file is long enough.
    ///
    /// This may return OS errors
    ///
    /// This may panic if the mutex is poisoned. If our code is not buggy, it will never happen.
    pub fn resize(&self, new_len: usize) -> Result<()> {
        // Wait for and acquire the append lock (so nobody can append)
        let _guard = self.append_lock.lock().unwrap();

        // Write lock the map
        let mut inner = self.inner.write().unwrap();

        // flush first
        inner.flush_range(0, inner.len())?;

        remap(self.fd, &mut inner, new_len)
    }

    pub fn get_end(&self) -> usize {
        let inner = self.inner.read().unwrap();
        let slice: &[u8] = unsafe { slice::from_raw_parts(inner.as_ptr(), HEADER_SIZE) };
        usize::from_le_bytes(slice[0..HEADER_SIZE].try_into().unwrap())
    }

    pub fn flush(&self) -> Result<()> {
        let len = self.len();
        let inner = self.inner.read().unwrap();
        inner.flush_range(0, len)
    }

    pub fn flush_async(&self) -> Result<()> {
        let len = self.len();
        let inner = self.inner.read().unwrap();
        inner.flush_async_range(0, len)
    }

    pub fn flush_range(&self, offset: usize, len: usize) -> Result<()> {
        let inner = self.inner.read().unwrap();
        inner.flush_range(offset, len)
    }

    pub fn flush_async_range(&self, offset: usize, len: usize) -> Result<()> {
        let inner = self.inner.read().unwrap();
        inner.flush_async_range(offset, len)
    }

    pub fn advise(&self, advice: Advice) -> Result<()> {
        let inner = self.inner.read().unwrap();
        inner.advise(advice)
    }

    pub fn advise_range(&self, advice: Advice, offset: usize, len: usize) -> Result<()> {
        let inner = self.inner.read().unwrap();
        inner.advise_range(advice, offset, len)
    }

    pub fn lock(&mut self) -> Result<()> {
        let inner = self.inner.read().unwrap();
        inner.lock()
    }

    pub fn unlock(&mut self) -> Result<()> {
        let inner = self.inner.read().unwrap();
        inner.unlock()
    }
}

#[cfg(feature = "stable_deref_trait")]
unsafe impl stable_deref_trait::StableDeref for MmapAppend {}

impl Deref for MmapAppend {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        let inner = self.inner.read().unwrap();
        unsafe { slice::from_raw_parts(inner.as_ptr(), self.get_end()) }
    }
}

impl AsRef<[u8]> for MmapAppend {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.deref()
    }
}

impl fmt::Debug for MmapAppend {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("MmapAppend")
            .field("ptr", &self.as_ptr())
            .field("len", &self.len())
            .finish()
    }
}

pub struct MmapRawDescriptor(RawFd);

pub trait MmapAsRawDesc {
    fn as_raw_desc(&self) -> MmapRawDescriptor;
}

impl MmapAsRawDesc for RawFd {
    fn as_raw_desc(&self) -> MmapRawDescriptor {
        MmapRawDescriptor(*self)
    }
}

impl<'a, T> MmapAsRawDesc for &'a T
where
    T: AsRawFd,
{
    fn as_raw_desc(&self) -> MmapRawDescriptor {
        MmapRawDescriptor(self.as_raw_fd())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_mmap_append() {
        use std::fs::OpenOptions;

        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("mmap");

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .unwrap();

        file.set_len(0 as u64).unwrap();

        // Verify it won't work if too small
        unsafe {
            assert!(MmapAppend::new(&file, true).is_err());
        }

        file.set_len(32 as u64).unwrap();
        let mmap = unsafe { MmapAppend::new(&file, true).unwrap() };
        assert_eq!(mmap.len(), 8); // only 8 bytes written so far

        assert_eq!(mmap.get_end(), HEADER_SIZE);

        let thirty_two_bytes: Vec<u8> = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ];

        // Not enough space
        assert!(mmap
            .append(thirty_two_bytes.len(), |s: &mut [u8]| s
                .copy_from_slice(&thirty_two_bytes))
            .is_err());

        // Resize
        mmap.resize(128).unwrap();

        mmap.append(thirty_two_bytes.len(), |s: &mut [u8]| {
            s.copy_from_slice(&thirty_two_bytes)
        })
        .unwrap();

        assert_eq!(mmap.get_end(), 32 + HEADER_SIZE);

        mmap.append(thirty_two_bytes.len(), |s: &mut [u8]| {
            s.copy_from_slice(&thirty_two_bytes)
        })
        .unwrap();

        assert_eq!(mmap.get_end(), 32 + 32 + HEADER_SIZE);
    }
}
