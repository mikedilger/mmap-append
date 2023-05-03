
mod advice;

mod inner;

use crate::advice::Advice;
use crate::inner::{MmapInner, file_len};

use std::fmt;
use std::io::{self, Result};
use std::ops::Deref;
use std::os::unix::io::{AsRawFd, RawFd};
use std::slice;
use std::sync::Mutex;

/// A handle to an append-only memory mapped buffer.
///
/// Only one writer may append at a time (the other writers will spin-wait). Readers are not
/// blocked while an append is taking place.
pub struct MmapAppend {
    // Only one writer may append at a time.
    append_lock: Mutex<()>,

    // This is the mmap. It has a usize at the beginning indicating where the end of the content lies
    pub(crate) inner: MmapInner,
}

impl MmapAppend {
    /// Creates Mmaps the `file` returning an MmapAppend object.
    ///
    /// If `initialize` is true, it writes the initial end marker setting the end of the
    /// data to right after the end marker.
    ///
    /// There is no offset and it does not populate.
    pub unsafe fn new<T: MmapAsRawDesc>(file: T, initialize: bool) -> Result<MmapAppend> {
        let u = std::mem::size_of::<usize>();

        // File must be long enough for a usize 'end' record at the front
        let desc = file.as_raw_desc();
        let file_len = file_len(desc.0)?;
        if (file_len as usize) < u {
            return Err(io::Error::new(io::ErrorKind::Other, "File not large enough."));
        }

        let mut map = MmapInner::map_mut(file_len as usize, desc.0, 0)?;

        if initialize {
            // write the end value to the beginning
            let slice: &mut [u8] = unsafe { &mut slice::from_raw_parts_mut(map.mut_ptr(), u) };
            slice[0..u].copy_from_slice(&u.to_le_bytes());
            map.flush(0, u)?;
        }

        Ok(MmapAppend {
            append_lock: Mutex::new(()),
            inner: map
        })
    }

    /// Append data.
    ///
    /// This will return an error if there is not enough space.
    ///
    /// This may panic if the mutex is poisoned. If our code is not buggy, it will never happen.
    pub fn append(&self, data: &[u8]) -> Result<()> {
        // Wait for and acquire the append lock
        let _guard = self.append_lock.lock().unwrap();

        // Define a slice over the map
        let u = std::mem::size_of::<usize>();
        let slice: &mut [u8] = unsafe {
            &mut slice::from_raw_parts_mut(self.inner.unsafe_mut_ptr(), self.inner.len())
        };

        // Read the end marker
        let mut end = usize::from_le_bytes(slice[0..u].try_into().unwrap());

        // Check available space
        if end + data.len() > self.inner.len() {
            return Err(io::Error::new(io::ErrorKind::Other, "Out of space"));
        }

        // Append
        slice[end..end + data.len()].copy_from_slice(data);

        // Overwrite the end marker
        end += data.len();
        slice[0..u].copy_from_slice(&end.to_le_bytes());

        Ok(())
    }

    /// Resize the map.
    ///
    /// This may return OS errors
    ///
    /// This may panic if the mutex is poisoned. If our code is not buggy, it will never happen.
    pub fn resize(&self, new_len: usize) -> Result<()> {
        // Wait for and acquire the append lock
        let _guard = self.append_lock.lock().unwrap();

        unsafe { self.inner.resize(new_len) }
    }

    pub fn get_end(&self) -> usize {
        let u = std::mem::size_of::<usize>();
        let slice: &[u8] = unsafe { &slice::from_raw_parts(self.inner.ptr(), u) };
        usize::from_le_bytes(slice[0..u].try_into().unwrap())
    }

    pub fn flush(&self) -> Result<()> {
        let len = self.len();
        self.inner.flush(0, len)
    }

    pub fn flush_async(&self) -> Result<()> {
        let len = self.len();
        self.inner.flush_async(0, len)
    }

    pub fn flush_range(&self, offset: usize, len: usize) -> Result<()> {
        self.inner.flush(offset, len)
    }

    pub fn flush_async_range(&self, offset: usize, len: usize) -> Result<()> {
        self.inner.flush_async(offset, len)
    }

    pub fn advise(&self, advice: Advice) -> Result<()> {
        self.inner.advise(advice, 0, self.inner.len())
    }

    pub fn advise_range(&self, advice: Advice, offset: usize, len: usize) -> Result<()> {
        self.inner.advise(advice, offset, len)
    }

    pub fn lock(&mut self) -> Result<()> {
        self.inner.lock()
    }

    pub fn unlock(&mut self) -> Result<()> {
        self.inner.unlock()
    }
}

#[cfg(feature = "stable_deref_trait")]
unsafe impl stable_deref_trait::StableDeref for MmapAppend {}

impl Deref for MmapAppend {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.inner.ptr(), self.inner.len()) }
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
        let mmap = unsafe {
            MmapAppend::new(&file, true).unwrap()
        };
        assert_eq!(mmap.len(), 32);

        assert_eq!(mmap.get_end(), std::mem::size_of::<usize>());

        let thirty_two_bytes: Vec<u8> = vec![
            0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
            16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
        ];

        // Not enough space
        assert!(
            mmap.append(&thirty_two_bytes).is_err()
        );

        // Resize
        mmap.resize(128).unwrap();

        mmap.append(&thirty_two_bytes).unwrap();

        assert_eq!(mmap.get_end(), 32 + std::mem::size_of::<usize>());

        mmap.append(&thirty_two_bytes).unwrap();

        assert_eq!(mmap.get_end(), 32 + 32 + std::mem::size_of::<usize>());
    }
}
