//! Output redirection example.
//!
//! This example uses the `3dslink --server` option for redirecting output from the 3DS back
//! to the device that sent the executable.
//!
//! For now, `cargo 3ds run` does not support this flag, so to run this example
//! it must be sent manually, like this:
//! ```sh
//! cargo 3ds build --example output-3dslink
//! 3dslink --server target/armv6k-nintendo-3ds/debug/examples/output-3dslink.3dsx
//! ```

use std::{time::Duration, net::{Ipv4Addr, SocketAddr, IpAddr}, rc::Rc, io::{self, Write}, mem::MaybeUninit, ffi::CString, slice, env};

use ctru::prelude::*;

const PORT: u16 = 17491;
const GDB_DEFAULT: bool = false;
const GDB_ENABLED_STR: &str = "\x1b[32;1menabled\x1b[0m";
const GDB_DISABLED_STR: &str = "\x1b[31;1mdisabled\x1b[0m";

fn main() {
    let gfx = Gfx::new().expect("Couldn't obtain GFX controller");
    let mut hid = Hid::new().expect("Couldn't obtain HID controller");
    let apt = Apt::new().expect("Couldn't obtain APT controller");

    // We need to use network sockets to send the data stream back.
    let mut soc = Soc::new().expect("Couldn't obtain SOC controller");
    let log_console = Console::new(gfx.bottom_screen.borrow_mut());
    let console = Console::new(gfx.top_screen.borrow_mut());
    dbg!(env::args());
    let mut gdb_state = GDB_DEFAULT;

    if !setup_3dslink(&soc, gdb_state) {
        return;
    }

    let mut recvbuf = [0u8; 256];

    while apt.main_loop() {
        hid.scan_input();

        let keys = hid.keys_down();
        if keys.contains(KeyPad::START) {
            break;
        }

        if keys.contains(KeyPad::X) {
            gdb_state = !gdb_state;
            console.clear();
            if !setup_3dslink(&soc, gdb_state) {
                break;
            }
        }

        if keys.contains(KeyPad::Y) {
            if exec_3dsx("sdmc:/3ds/ci-3dslink.3dsx", &[]).is_ok() {
                return;
            } else {
                println!("\x1b[31;1mCouldn't run 3dsx!\x1b[0m")
            }
        }

        gfx.wait_for_vblank();
    }
}

fn setup_3dslink(soc: &Soc, gdb_state: bool) -> bool {
    println!("ci-3dslink by Lena\n");
    println!("Checking for network...");
    let addr = soc.host_address();
    if addr.is_unspecified() {
        println!("\x1b[31;5mNo network connection. Exiting in 5 seconds...\x1b[0m");
        std::thread::sleep(Duration::from_millis(5000));
        return false;
    }

    let gdb_str = if gdb_state {GDB_ENABLED_STR} else {GDB_DISABLED_STR};
    println!("\nAddress: \x1b[32;1m{}\x1b[0m Port: \x1b[32;1m{PORT}\x1b[0m GDB: {}\n", addr, gdb_str);

    println!("Waiting for a 3dslink connection...\n");
    println!("Press START to exit, X to toggle GDB.\n");

    true
}

fn netloader_activate(endpoint: &str) -> io::Result<()> {
    let broadcast_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), PORT);

    return Ok(());
}


fn exec_3dsx(path: &str, args: &[&str]) -> Result<(), ()> {

    // handle args

    // first u32 is the number of arguments
    // the rest is the arguments all null terminated
    let mut buf = [0u32; 0x400 / 4];

    let (len, char_buf) = buf.split_at_mut(1);
    let len = &mut len[0];
    // turn the char buf into a buffer of c_char (u8)
    // SAFETY: trust me bro
    // TODO: is there a safe way to do this? theres gotta be
    let mut char_buf = unsafe {
        std::slice::from_raw_parts_mut(char_buf.as_mut_ptr() as *mut u8, char_buf.len() * 4)
    };

    // write the path as the first string
    {
        let sized_buf = &mut char_buf[..path.len()];
        sized_buf.copy_from_slice(path.as_bytes());
    }
    // null terminate it
    char_buf[path.len()] = 0;

    // increase number of args
    *len += 1;

    // set the slice beginning to the end of the previous string (dont forget the terminator)
    char_buf = &mut char_buf[(path.len() + 1)..];

    // write all the other arguments
    for s in args {
        // write the argument to the buffer
        {
            let sized_buf = &mut char_buf[..s.len()];
            sized_buf.copy_from_slice(s.as_bytes());
        }
        // null terminate it
        char_buf[s.len()] = 0;

        // increase number of args
        *len += 1;

        // set the slice beginning to the end of the previous string (dont forget the terminator)
        char_buf = &mut char_buf[(s.len() + 1)..];
    }

    println!("{}", std::mem::size_of_val(&buf[..]));
    launch_3dsx(path, &buf[..])
}

fn build_argv(path: &str, args: &[&str]) -> ([u8; 0x400], usize) {
    let mut buf = [0u8; 0x400];

    let mut i = 0;

    let num_args = (args.len() + 1) as u32;
    buf[..4].copy_from_slice(&num_args.to_le_bytes());
    i += 4;

    let iter = std::iter::once(&path).chain(args);

    for arg in iter {
        buf[i..][..arg.len()].copy_from_slice(arg.as_bytes());
        i += arg.len();
        //buf[i] = 0; // redundant
        i += 1;
    }

    (buf, i)
}

fn launch_3dsx(path: &str, argv: &[u32]) -> Result<(), ()> {
    let path = if path.starts_with("sdmc:/") {
        &path[5..]
    } else {
        path
    };

    if let Some(handle) = LdrHandle::new() {
        unsafe {
            if !set_target(path, &handle) {
                return Err(());
            }
    
            if !set_argv(&argv, &handle) {
                return Err(());
            }
        }

        return Ok(())
    }

    Err(())
}

unsafe fn set_target(path: &str, handle: &LdrHandle) -> bool {

    let path_c = match CString::new(path) {
        Ok(p) => p,
        Err(_) => return false
    };

    let cmdbuf_ptr: *mut u32 = ctru_sys::getThreadCommandBuffer();
    let cmdbuf = slice::from_raw_parts_mut(cmdbuf_ptr, 8);

    cmdbuf[0] = ctru_sys::IPC_MakeHeader(2, 0, 2); // 0x20002
    cmdbuf[1] = ctru_sys::IPC_Desc_StaticBuffer(path.len() + 1, 0);
    cmdbuf[2] = path_c.as_ptr() as u32;

    ctru_sys::R_SUCCEEDED(ctru_sys::svcSendSyncRequest(*handle.get_handle()))
}

unsafe fn set_argv(args: &[u32], handle: &LdrHandle) -> bool {
    let cmdbuf_ptr: *mut u32 = ctru_sys::getThreadCommandBuffer();
    let cmdbuf = slice::from_raw_parts_mut(cmdbuf_ptr, 8);

    cmdbuf[0] = ctru_sys::IPC_MakeHeader(3, 0, 2); // 0x30002
    cmdbuf[1] = ctru_sys::IPC_Desc_StaticBuffer(std::mem::size_of_val(&args),1);
    cmdbuf[2] = args.as_ptr() as u32;

    ctru_sys::R_SUCCEEDED(ctru_sys::svcSendSyncRequest(*handle.get_handle()))
}

struct LdrHandle {
    handle: ctru_sys::Handle
}

impl LdrHandle {
    /// SAFETY: DO NOT EVER CALL THIS TWICE
    pub fn new() -> Option<LdrHandle> {
        let mut handle: MaybeUninit<ctru_sys::Handle> = MaybeUninit::uninit();
        unsafe {
            if !ctru_sys::R_SUCCEEDED(ctru_sys::svcConnectToPort(handle.as_mut_ptr(), b"hb:ldr".as_ptr())) {
                return None;
            }
        }
    
        let handle = unsafe { handle.assume_init() };

        Some(LdrHandle {
            handle
        })
    }

    pub fn get_handle<'a>(&'a self) -> &ctru_sys::Handle {
        &self.handle
    }
}

impl Drop for LdrHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = ctru_sys::svcCloseHandle(self.handle);
        }
    }
}