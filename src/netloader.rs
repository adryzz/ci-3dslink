use std::{
    fs::File, io::{self, Read, Write}, net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket}
};
//use flate2::read::ZlibDecoder;
pub const PORT: u16 = 17491;
pub const MAX_FILENAME: usize = 256;

#[derive(Debug)]
pub struct Netloader {
    broadcastsock: UdpSocket,
    listensock: TcpListener,
    status: NetloaderStatus,
}

#[derive(Debug)]
/// The status this Netloader is in
pub enum NetloaderStatus {
    /// Listening for UDP broadcast messages on port 17491.
    /// 
    /// When receiving the "3dsboot" message, it sends "boot3ds" on port 17491 to that device,
    ///  and enters [NetloaderStatus::WaitingForTCP] status.
    Listening,
    /// Waiting for a TCP connection on port 17491.
    /// 
    /// When a connection from the ip address arrives, it enters [NetloaderStatus::FileInfo] status.
    /// 
    /// After waiting for 10 frames without a connection, it goes back to [NetloaderStatus::Listening] status.
    WaitingForTCP(IpAddr, u32),
    /// Waiting for information about the file to be received.
    /// 
    /// File name length ([u32]), File name, File size ([u32])
    /// 
    /// After receiving those, it replies with an Ok (0) or Err (-1) [u32].
    /// 
    /// If there aren't any errors, it enters [NetloaderStatus::File] status, otherwise it goes back to [NetloaderStatus::Listening] status.
    FileInfo(TcpStream),
    /// Receiving the file, ZLIB compressed. If there are any errors it goes back to [NetloaderStatus::Listening] status.
    /// 
    /// At the end of the ZLIB stream, it replies with an Ok (0) or Err (-1) [u32], and enters [NetloaderStatus::Arguments] status.
    File(TcpStream, File),
    /// Receiving the program arguments.
    /// 
    /// Length ([u32]), and arguments TODO
    Arguments(TcpStream),
}

impl Netloader {
    pub fn new() -> io::Result<Self> {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), PORT);

        let broadcastsock = UdpSocket::bind(addr)?;
        broadcastsock.set_nonblocking(true)?;

        let listensock = TcpListener::bind(addr)?;
        listensock.set_nonblocking(true)?;

        Ok(Self {
            broadcastsock,
            listensock,
            status: NetloaderStatus::Listening
        })
    }

    pub fn netloader_task(&mut self, recv_buf: &mut [u8]) -> io::Result<()> {
        match self.netloader_task_err(recv_buf) {
            Ok(r) => return Ok(r),
            Err(e) => {
                // only error out if in listening mode, otherwise get back to listening
                match self.status {
                    NetloaderStatus::Listening => return Err(e),
                    NetloaderStatus::WaitingForTCP(_, _) => {
                        eprintln!("Error while accepting connection, going back to listening");
                    },
                    NetloaderStatus::FileInfo(_) => {
                        // TODO: send -1
                        eprintln!("Error while reading file info, going back to listening");
                    },
                    NetloaderStatus::File(_, _) => {
                        // TODO: send -1
                        eprintln!("Error while reading file, going back to listening");
                    },
                    NetloaderStatus::Arguments(_) => {
                        eprintln!("Error while reading arguments, going back to listening");
                    },
                }
                eprintln!("{}", e);
            },
        }
        self.status = NetloaderStatus::Listening;
        Ok(())
    }

    fn netloader_task_err(&mut self, recv_buf: &mut [u8]) -> io::Result<()> {
        match &mut self.status {
            NetloaderStatus::Listening => {
                let (_read, src) = match self.broadcastsock.recv_from(recv_buf) {
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
                    self.broadcastsock.send_to(b"boot3ds", SocketAddr::new(src.ip(), PORT))?;
                    println!("Entering WaitingForTCP status.");
                    self.status = NetloaderStatus::WaitingForTCP(src.ip(), 0);
                }

                Ok(())
            },
            NetloaderStatus::WaitingForTCP(ip, wait_count) => {
                if *wait_count == 10 {
                    println!("No connection, going back to Listening status.");
                    self.status = NetloaderStatus::Listening;
                    return Ok(());
                }

                match self.listensock.accept() {
                    Ok((stream, addr)) => {
                        if addr.ip() == *ip {
                            println!("Entering FileInfo status.");
                            self.status = NetloaderStatus::FileInfo(stream);
                            return Ok(());
                        } else {
                            println!("Connection from wrong address, closing and waiting.");
                            // connection is dropped by rust
                            return Ok(());
                        }
                    }
                    Err(e) => {
                        if e.kind() == io::ErrorKind::WouldBlock {
                            return Ok(());
                        } else {
                            return Err(e);
                        }
                    }
                }
            },
            NetloaderStatus::FileInfo(stream) => {
                // receive the length of the filename
                let mut namelen_buf = [0u8; 4];
                stream.read_exact(&mut namelen_buf)?;
                let namelen = u32::from_le_bytes(namelen_buf) as usize;
                if namelen > MAX_FILENAME {
                    println!("File name way too long! ({})", namelen);
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid input"));
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

                // send back an OK
                stream.write(&[0, 0, 0, 0])?;

                // TODO: VERY MUCH FIXME, THIS IS BAD (BUT WORKS FOR NOW)
                self.status = NetloaderStatus::File(unsafe {std::ptr::read(stream as *mut TcpStream)}, file);

                Ok(())
            },
            NetloaderStatus::File(s, f) => return Err(io::Error::new(io::ErrorKind::Unsupported, "Not Implemented Yet")),
            NetloaderStatus::Arguments(s) => return Err(io::Error::new(io::ErrorKind::Unsupported, "Not Implemented Yet")),
        }
    }
}