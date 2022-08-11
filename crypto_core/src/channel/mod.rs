pub mod mem_channel;
pub mod net_channel;

pub use mem_channel::*;
pub use net_channel::*;

use std::{
    cell::RefCell,
    io::{Read, Result, Write},
    rc::Rc,
};

use crate::{
    utils::{pack_bits, unpack_bits},
    Block,
};

/// A trait for I/O channel.
pub trait IOChannel {
    /// Write bytes slice to the channel.
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()>;
    /// Read bytes slice from the channel.
    fn read_bytes(&mut self, bytes: &mut [u8]) -> Result<()>;
    /// Flush the channel.
    fn flush(&mut self) -> Result<()>;

    /// Write a `bool` to the channel.
    #[inline(always)]
    fn write_bool(&mut self, b: bool) -> Result<()> {
        self.write_bytes(&[b as u8])
    }

    /// Write a `bool` vector to the channel.
    #[inline(always)]
    fn write_bools(&mut self, bits: &[bool]) -> Result<()> {
        let bit_vec = pack_bits(bits);
        self.write_bytes(&bit_vec)
    }

    /// Read a `bool` from the channel.
    #[inline(always)]
    fn read_bool(&mut self) -> Result<bool> {
        let mut data = [0u8; 1];
        self.read_bytes(&mut data)?;
        Ok(data[0] != 0)
    }

    /// Read a `bool` vector from the channel.
    #[inline(always)]
    fn read_bools(&mut self) -> Result<Vec<bool>> {
        let mut bit_vec = Vec::new();
        self.read_bytes(&mut bit_vec)?;
        Ok(unpack_bits(&bit_vec, bit_vec.len()))
    }

    /// Write a `Block` to the channel.
    #[inline(always)]
    fn write_block(&mut self, blk: &Block) -> Result<()> {
        self.write_bytes(blk.as_ref())
    }

    /// Read a `Block` from the channel.
    #[inline(always)]
    fn read_block(&mut self) -> Result<Block> {
        let mut blk = Block::default();
        self.read_bytes(blk.as_mut())?;
        Ok(blk)
    }
}

/// A standard channel that implements `IOChannel`
pub struct StdChannel<R, W> {
    reader: Rc<RefCell<R>>,
    writer: Rc<RefCell<W>>,

    read_bytes_size: usize,
    write_bytes_size: usize,
}

impl<R: Read, W: Write> StdChannel<R, W> {
    /// New a `StdChannel`
    pub fn new(reader: R, writer: W) -> Self {
        let reader = Rc::new(RefCell::new(reader));
        let writer = Rc::new(RefCell::new(writer));

        Self {
            reader,
            writer,
            read_bytes_size: 0,
            write_bytes_size: 0,
        }
    }

    /// Return a reader object wrapped in `Rc<RefCell>`
    pub fn reader(self) -> Rc<RefCell<R>> {
        self.reader
    }

    /// Return a writer object wrapped in `Rc<RefCell>`
    pub fn writer(self) -> Rc<RefCell<W>> {
        self.writer
    }

    /// Return `write_bytes`
    pub fn wirte_bytes(&self) -> usize {
        self.write_bytes_size
    }

    /// Return `read_bytes`
    pub fn read_bytes(&self) -> usize {
        self.read_bytes_size
    }
}

impl<R: Read, W: Write> IOChannel for StdChannel<R, W> {
    #[inline(always)]
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.writer.borrow_mut().write_all(bytes)?;
        self.write_bytes_size += bytes.len();
        Ok(())
    }

    #[inline(always)]
    fn read_bytes(&mut self, mut bytes: &mut [u8]) -> Result<()> {
        self.reader.borrow_mut().read_exact(&mut bytes)?;
        self.read_bytes_size += bytes.len();
        Ok(())
    }

    #[inline(always)]
    fn flush(&mut self) -> Result<()> {
        self.writer.borrow_mut().flush()
    }
}

/// Standard symmetric stream implement `IOChannel`
pub struct SymChannel<S> {
    stream: Rc<RefCell<S>>,
    read_bytes: usize,
    write_bytes: usize,
}

impl<S: Read + Write> SymChannel<S> {
    ///New a `SymChannel`
    pub fn new(stream: S) -> Self {
        let stream = Rc::new(RefCell::new(stream));
        Self {
            stream,
            read_bytes: 0,
            write_bytes: 0,
        }
    }
}

impl<S: Read + Write> IOChannel for SymChannel<S> {
    #[inline(always)]
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.stream.borrow_mut().write_all(bytes)?;
        self.write_bytes += bytes.len();
        Ok(())
    }

    #[inline(always)]
    fn read_bytes(&mut self, mut bytes: &mut [u8]) -> Result<()> {
        self.stream.borrow_mut().read_exact(&mut bytes)?;
        self.read_bytes += bytes.len();
        Ok(())
    }

    #[inline(always)]
    fn flush(&mut self) -> Result<()> {
        self.stream.borrow_mut().flush()
    }
}
