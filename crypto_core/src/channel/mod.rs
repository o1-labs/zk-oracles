pub mod local_channel;
pub mod net_channel;

pub use local_channel::*;
pub use net_channel::*;

use std::{
    cell::RefCell,
    io::{Read, Result, Write},
    rc::Rc,
    sync::{Arc, Mutex},
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
    flush_num: usize,
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
            flush_num: 0,
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

    /// Return `write_bytes_size`
    pub fn wirte_bytes_size(&self) -> usize {
        self.write_bytes_size
    }

    /// Return `read_bytes_size`
    pub fn read_bytes_size(&self) -> usize {
        self.read_bytes_size
    }

    /// Return `flush_num`
    pub fn flush_num(&self) -> usize {
        self.flush_num
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
        self.writer.borrow_mut().flush()?;
        self.flush_num += 1;
        Ok(())
    }
}

/// A sync channel that implements `IOChannel`.
pub struct SynChannel<R, W> {
    reader: Arc<Mutex<R>>,
    writer: Arc<Mutex<W>>,

    read_bytes_size: usize,
    write_bytes_size: usize,
    flush_num: usize,
}

impl<R: Read, W: Write> SynChannel<R, W> {
    /// New a `SynChannel`
    pub fn new(reader: R, writer: W) -> Self {
        let reader = Arc::new(Mutex::new(reader));
        let writer = Arc::new(Mutex::new(writer));

        Self {
            reader,
            writer,
            read_bytes_size: 0,
            write_bytes_size: 0,
            flush_num: 0,
        }
    }

    /// Return a reader object wrapped in `Rc<RefCell>`
    pub fn reader(self) -> Arc<Mutex<R>> {
        self.reader
    }

    /// Return a writer object wrapped in `Rc<RefCell>`
    pub fn writer(self) -> Arc<Mutex<W>> {
        self.writer
    }

    /// Return `write_bytes_size`
    pub fn wirte_bytes_size(&self) -> usize {
        self.write_bytes_size
    }

    /// Return `read_bytes_size`
    pub fn read_bytes_size(&self) -> usize {
        self.read_bytes_size
    }

    /// Return `flush_num`
    pub fn flush_num(&self) -> usize {
        self.flush_num
    }
}

impl<R: Read, W: Write> IOChannel for SynChannel<R, W> {
    #[inline(always)]
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.writer.lock().unwrap().write_all(bytes)?;
        self.write_bytes_size += bytes.len();
        Ok(())
    }

    #[inline(always)]
    fn read_bytes(&mut self, mut bytes: &mut [u8]) -> Result<()> {
        self.reader.lock().unwrap().read_exact(&mut bytes)?;
        self.read_bytes_size += bytes.len();
        Ok(())
    }

    #[inline(always)]
    fn flush(&mut self) -> Result<()> {
        self.writer.lock().unwrap().flush()?;
        self.flush_num += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
        thread,
    };

    use rand::random;
    use crate::{IOChannel, StdChannel};

    #[test]
    fn channel_test() {
        //let (mut sender, mut receiver) = local_channel_pair();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let send_bytes = random::<[u8; 10]>();
        let mut recv_bytes_ = [0u8; 12];

        let handle = thread::spawn(move || {
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = StdChannel::new(reader, writer);

            channel.write_bytes(&send_bytes).unwrap();
            channel.flush().unwrap();

            channel.read_bytes(&mut recv_bytes_).unwrap();
        });

        let mut recv_bytes = [0u8; 10];
        let send_bytes_ = random::<[u8; 12]>();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = StdChannel::new(reader, writer);

        channel.read_bytes(&mut recv_bytes).unwrap();
        channel.write_bytes(&send_bytes_).unwrap();
        channel.flush().unwrap();

        assert_eq!(send_bytes, recv_bytes);

        handle.join().unwrap();
    }
}
