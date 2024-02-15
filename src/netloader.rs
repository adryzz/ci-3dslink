use std::{
    fs::File, io::{self, Read, Write}, net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket}
};
use flate2::read::ZlibDecoder;
pub const PORT: u16 = 17491;

#[derive(Debug)]
pub struct Netloader {
    broadcastsock: UdpSocket,
    listensock: TcpListener,
    wait_count: u32,
    stream: Option<TcpStream>,
    file: Option<FileInfo>,
}

#[derive(Debug)]
pub struct FileInfo {
    bytes_received: usize,
    file: File
}

impl Netloader {
    pub fn new(addr: IpAddr) -> io::Result<Self> {
        let broadcast = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), PORT);
        let broadcastsock = UdpSocket::bind(broadcast)?;
        broadcastsock.set_nonblocking(true)?;

        let ip = SocketAddr::new(addr, PORT);
        let listensock = TcpListener::bind(ip)?;
        listensock.set_nonblocking(true)?;

        Ok(Self {
            broadcastsock,
            listensock,
            stream: None,
            file: None,
            wait_count: 0
        })
    }

    pub fn netloader_task(&mut self, recv_buf: &mut [u8]) -> io::Result<Option<String>> {
        if self.stream.is_some() {
            let file = self.recv_task(recv_buf)?;
            return Ok(file);
        } else {
            self.listen_task(recv_buf)?;
            return Ok(None);
        }
    }

    fn listen_task(&mut self, recv_buf: &mut [u8]) -> io::Result<()> {
        if self.wait_count == 0 {
            let (read, src) = match self.broadcastsock.recv_from(recv_buf) {
                Ok(r) => r,
                Err(e) => {
                    if e.kind() == io::ErrorKind::WouldBlock {
                        return Ok(());
                    } else {
                        return Err(e);
                    }
                }
            };
    
            if &recv_buf[..7] == b"3dsboot" {
                println!("received \"3dsboot\" message");
                // send to a different port
                self.broadcastsock.send_to(b"boot3ds", SocketAddr::new(src.ip(), PORT))?;
                println!("sending \"boot3ds\" message");
                self.wait_count += 1;
            }
        } else {
            println!("waiting for connection");
            self.wait_count += 1;
            match self.listensock.accept() {
                Ok((stream, addr)) => {
                    self.stream = Some(stream);
                    println!("stream good");
                }
                Err(e) => {
                    if e.kind() == io::ErrorKind::WouldBlock {
                        return Ok(());
                    } else {
                        return Err(e);
                    }
                }
            }
        }
        if self.wait_count == 10 {
            self.wait_count = 0;
        }
        Ok(())
    }

    fn recv_task(&mut self, recv_buf: &mut [u8]) -> io::Result<Option<String>> {
        if let Some(stream) = &mut self.stream {

            if let Some(file) = &mut self.file {
            } else {
                // receive the length of the filename
                let mut namelen_buf = [0u8; 4];
                stream.read_exact(&mut namelen_buf)?;
                let namelen = u32::from_le_bytes(namelen_buf) as usize;
                if namelen > recv_buf.len() {
                    stream.shutdown(std::net::Shutdown::Both)?;
                    println!("name long bad");
                    self.stream = None;
                    return Ok(None);
                }

                // receive the filename and create/open the file
                let namebuf = &mut recv_buf[..namelen];
                stream.read_exact(namebuf)?;

                let mut fullpath_buf = Vec::with_capacity(5+namebuf.len());
                fullpath_buf.extend_from_slice(b"/3ds/");
                fullpath_buf.extend_from_slice(namebuf);
                
                let fullpath = String::from_utf8(fullpath_buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
                println!("file path: {}", &fullpath);
                let file = File::create(fullpath)?;

                // read the file length and set it
                let mut filelen_buf = [0u8; 4];
                stream.read_exact(&mut filelen_buf)?;
                let filelen = u32::from_le_bytes(filelen_buf);
                file.set_len(filelen as u64)?;
                println!("file length: {}", filelen);

                self.file = Some(FileInfo {
                    file,
                    bytes_received: 0
                });

                stream.write(&[0, 0, 0, 0])?;
            }

        }
        Ok(None)
    }
}