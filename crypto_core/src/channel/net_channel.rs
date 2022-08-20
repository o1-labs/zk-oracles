use crate::AbstractChannel;
use std::io::Result;
use std::{
    cell::RefCell,
    io::{BufReader, BufWriter, Read, Write},
    net::{TcpListener, TcpStream, ToSocketAddrs},
    rc::Rc,
};
use structopt::StructOpt;

pub struct NetChannel<R: Read, W: Write> {
    is_server: bool,
    reader: Rc<RefCell<BufReader<R>>>,
    writer: Rc<RefCell<BufWriter<W>>>,
    read_bytes_size: usize,
    write_bytes_size: usize,
    flush_num: usize,
}

impl NetChannel<TcpStream, TcpStream> {
    pub fn new<A: ToSocketAddrs>(is_server: bool, addr: A) -> Self {
        if is_server {
            let listener = TcpListener::bind(addr).unwrap();
            match listener.accept() {
                Ok((socket, _)) => {
                    println!("connected");
                    Self {
                        is_server,
                        reader: Rc::new(RefCell::new(BufReader::new(socket.try_clone().unwrap()))),
                        writer: Rc::new(RefCell::new(BufWriter::new(socket))),
                        read_bytes_size: 0,
                        write_bytes_size: 0,
                        flush_num: 0,
                    }
                }
                Err(e) => {
                    panic!("could not get client: {e:?}");
                }
            }
        } else {
            match TcpStream::connect(addr) {
                Ok(socket) => {
                    println!("connected");
                    Self {
                        is_server,
                        reader: Rc::new(RefCell::new(BufReader::new(socket.try_clone().unwrap()))),
                        writer: Rc::new(RefCell::new(BufWriter::new(socket))),
                        read_bytes_size: 0,
                        write_bytes_size: 0,
                        flush_num: 0,
                    }
                }
                Err(e) => {
                    panic!("could not get server: {e:?}");
                }
            }
        }
    }

    pub fn is_server(&self) -> bool {
        self.is_server
    }
}

impl<R: Read, W: Write> AbstractChannel for NetChannel<R, W> {
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

#[derive(StructOpt, Debug)]
pub struct CommandLineOpt {
    #[structopt(short, long, default_value = "-1")]
    pub is_server: u32,
}
