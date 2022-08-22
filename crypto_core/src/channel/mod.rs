pub mod local_channel;
pub mod net_channel;

pub use local_channel::*;
pub use net_channel::*;

use crate::{
    utils::{pack_bits, unpack_bits},
    Block,
};
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use std::{
    cell::RefCell,
    io::{Read, Result, Write},
    rc::Rc,
    sync::{Arc, Mutex},
};

/// A trait for Abstract channel.
pub trait AbstractChannel {
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

    /// Write a `bool` slice to the channel.
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
    fn read_bools(&mut self, size: usize) -> Result<Vec<bool>> {
        let mut bit_vec = vec![0u8; (size - 1) / 8 + 1];
        self.read_bytes(&mut bit_vec)?;
        Ok(unpack_bits(&bit_vec, size))
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

    /// Write a Edwards point to the channel.
    #[inline(always)]
    fn write_point(&mut self, point: &EdwardsPoint) -> Result<()> {
        self.write_bytes(point.compress().as_bytes())?;
        Ok(())
    }

    /// Read a Edwards point from the channel.
    #[inline(always)]
    fn read_point(&mut self) -> Result<EdwardsPoint> {
        let mut data = [0u8; 32];
        self.read_bytes(&mut data)?;

        let point = match CompressedEdwardsY::from_slice(&data).decompress() {
            Some(point) => point,
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unable to decompress Edwards point",
                ));
            }
        };
        Ok(point)
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
    pub fn write_bytes_size(&self) -> usize {
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

impl<R: Read, W: Write> AbstractChannel for StdChannel<R, W> {
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

impl<R: Read, W: Write> AbstractChannel for SynChannel<R, W> {
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

    use crate::{local_channel_pair, AbstractChannel, Block, StdChannel};
    use curve25519_dalek::{constants, scalar::Scalar};
    use rand::random;

    #[test]
    fn std_channel_test() {
        let (tx, rx) = UnixStream::pair().unwrap();
        let send_bytes = random::<[u8; 10]>();
        let send_bool = random::<bool>();
        let send_bools = random::<[bool; 10]>();
        let send_block = random::<Block>();
        let x = Scalar::from(random::<u128>());
        let send_point = x * constants::ED25519_BASEPOINT_POINT;

        let handle = thread::spawn(move || {
            let reader = BufReader::new(tx.try_clone().unwrap());
            let writer = BufWriter::new(tx);
            let mut channel = StdChannel::new(reader, writer);

            channel.write_bytes(&send_bytes).unwrap();
            channel.write_bool(send_bool).unwrap();
            channel.write_bools(&send_bools).unwrap();
            channel.write_block(&send_block).unwrap();
            channel.write_point(&send_point).unwrap();

            channel.flush().unwrap();
        });

        let mut recv_bytes = [0u8; 10];

        let reader = BufReader::new(rx.try_clone().unwrap());
        let writer = BufWriter::new(rx);
        let mut channel = StdChannel::new(reader, writer);

        channel.read_bytes(&mut recv_bytes).unwrap();
        let recv_bool = channel.read_bool().unwrap();
        let recv_bools = channel.read_bools(10).unwrap();
        let recv_block = channel.read_block().unwrap();
        let recv_point = channel.read_point().unwrap();

        assert_eq!(send_bytes, recv_bytes);
        assert_eq!(send_bool, recv_bool);
        assert_eq!(send_bools.to_vec(), recv_bools);
        assert_eq!(send_block, recv_block);
        assert_eq!(send_point, recv_point);

        handle.join().unwrap();
    }

    #[test]
    fn local_channel_test() {
        let (mut sender, mut receiver) = local_channel_pair();

        let send_bytes = random::<[u8; 10]>();
        let send_bool = random::<bool>();
        let send_bools = random::<[bool; 10]>();
        let send_block = random::<Block>();
        let x = Scalar::from(random::<u128>());
        let send_point = x * constants::ED25519_BASEPOINT_POINT;

        let handle = thread::spawn(move || {
            sender.write_bytes(&send_bytes).unwrap();
            sender.write_bool(send_bool).unwrap();
            sender.write_bools(&send_bools).unwrap();
            sender.write_block(&send_block).unwrap();
            sender.write_point(&send_point).unwrap();


            sender.flush().unwrap();
        });

        let mut recv_bytes = [0u8; 10];
        receiver.read_bytes(&mut recv_bytes).unwrap();
        let recv_bool = receiver.read_bool().unwrap();
        let recv_bools = receiver.read_bools(10).unwrap();
        let recv_block = receiver.read_block().unwrap();
        let recv_point = receiver.read_point().unwrap();


        assert_eq!(send_bytes, recv_bytes);
        assert_eq!(send_bool, recv_bool);
        assert_eq!(send_bools.to_vec(), recv_bools);
        assert_eq!(send_block, recv_block);
        assert_eq!(send_point, recv_point);

        handle.join().unwrap();
    }
}
