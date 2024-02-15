mod logger;
mod netloader;

use std::{
    env,
    ffi::CString,
    mem::MaybeUninit,
    slice,
    time::Duration,
};

use ctru::prelude::*;

use crate::netloader::Netloader;
const GDB_DEFAULT: bool = false;
const GDB_ENABLED_STR: &str = "\x1b[32;1menabled\x1b[0m";
const GDB_DISABLED_STR: &str = "\x1b[31;1mdisabled\x1b[0m";
const TEST_PASS_STR: &str = "\x1b[32;1mpass\x1b[0m";
const TEST_FAIL_STR: &str = "\x1b[31;1mfail\x1b[0m";

fn main() {
    let (gfx, mut hid, apt, mut soc) = startup();
    // We need to use network sockets to send the data stream back.
    let log_console = Console::new(gfx.bottom_screen.borrow_mut());
    // bottom screen can hold 28 lines
    let console = Console::new(gfx.top_screen.borrow_mut());
    let luma3ds = check_luma3ds();
    dbg!(env::args());
    let mut gdb_state = GDB_DEFAULT && luma3ds;

    if !check_3dslink(&soc, gdb_state) {
        return;
    }

    let mut netloader = Netloader::new().unwrap();

    let mut recv_buf = [0u8; 64*1024];

    while apt.main_loop() {
        hid.scan_input();

        let keys = hid.keys_down();
        if keys.contains(KeyPad::START) {
            break;
        }

        if keys.contains(KeyPad::X) {
            if luma3ds {
                gdb_state = !gdb_state;
            }
            console.clear();
            if !check_3dslink(&soc, gdb_state) {
                break;
            }
            if !luma3ds {
                println!("\x1b[31;1mCannot enable GDB without Luma3DS!\x1b[0m");
            }
        }

        if keys.contains(KeyPad::Y) {
            if launch_3dsx("sdmc:/3ds/ci-3dslink.3dsx", &[]) {
                return;
            } else {
                println!("\x1b[31;1mCouldn't run 3dsx!\x1b[0m")
            }
        }

        netloader.netloader_task(&mut recv_buf).unwrap();
        gfx.wait_for_vblank();
    }
}

fn startup() -> (Gfx, Hid, Apt, Soc) {
    let gfx = Gfx::new().expect("Couldn't obtain GFX controller");
    let hid = Hid::new().expect("Couldn't obtain HID controller");
    let apt = Apt::new().expect("Couldn't obtain APT controller");
    let soc = Soc::new().expect("Couldn't obtain SOC controller");

    (gfx, hid, apt, soc)
}

fn check_luma3ds() -> bool {
    LdrHandle::new().is_some()
}

fn check_3dslink(soc: &Soc, gdb_state: bool) -> bool {
    println!("ci-3dslink by Lena\n");
    println!("Checking for network...");
    let addr = soc.host_address();
    if addr.is_unspecified() {
        println!("\x1b[31;5mNo network connection. Exiting in 5 seconds...\x1b[0m");
        std::thread::sleep(Duration::from_millis(5000));
        return false;
    }

    let gdb_str = if gdb_state {
        GDB_ENABLED_STR
    } else {
        GDB_DISABLED_STR
    };
    println!(
        "\nAddress: \x1b[32;1m{}\x1b[0m Port: \x1b[32;1m{}\x1b[0m GDB: {}\n",
        addr,
        netloader::PORT,
        gdb_str
    );

    println!("Waiting for a 3dslink connection...\n");
    println!("Press START to exit, X to toggle GDB.\n");

    true
}

fn build_argv(path: &str, args: &[&str]) -> ([u8; 0x400], usize) {
    let mut buf = [0u8; 0x400];

    // first u32 is the number of arguments
    // the rest is the arguments all null terminated
    let mut i = 0;

    // write the path as the first string
    let num_args = (args.len() + 1) as u32;
    buf[..4].copy_from_slice(&num_args.to_le_bytes());
    i += 4;

    let iter = std::iter::once(&path).chain(args).copied();

    // write all the other arguments
    for arg in iter {
        buf[i..][..arg.len()].copy_from_slice(arg.as_bytes());
        i += arg.len();
        //buf[i] = 0; // redundant
        i += 1;
    }

    (buf, i)
}

fn launch_3dsx(path: &str, args: &[&str]) -> bool {
    let path = if path.starts_with("sdmc:/") {
        &path[5..]
    } else {
        path
    };

    let (argv, _) = build_argv(path, args);

    if !load_rosalina(path, &argv) {
        println!("Rosalina 3dsx loader failed, using hax2");
        if !load_hax2(path, &argv) {
            return false;
        }
    }

    true
}

fn load_hax2(path: &str, argv: &[u8]) -> bool {
    false
}

fn load_rosalina(path: &str, argv: &[u8]) -> bool {
    if let Some(handle) = LdrHandle::new() {
        unsafe {
            if !set_target(path, &handle) {
                return false;
            }

            if !set_argv(&argv, &handle) {
                return false;
            }
        }

        return true;
    }

    return false;
}

unsafe fn set_target(path: &str, handle: &LdrHandle) -> bool {
    let path_c = match CString::new(path) {
        Ok(p) => p,
        Err(_) => return false,
    };

    let cmdbuf_ptr: *mut u32 = ctru_sys::getThreadCommandBuffer();
    let cmdbuf = slice::from_raw_parts_mut(cmdbuf_ptr, 8);

    cmdbuf[0] = ctru_sys::IPC_MakeHeader(2, 0, 2); // 0x20002
    cmdbuf[1] = ctru_sys::IPC_Desc_StaticBuffer(path.len() + 1, 0);
    cmdbuf[2] = path_c.as_ptr() as u32;

    ctru_sys::R_SUCCEEDED(ctru_sys::svcSendSyncRequest(*handle.get_handle()))
}

unsafe fn set_argv(args: &[u8], handle: &LdrHandle) -> bool {
    let cmdbuf_ptr: *mut u32 = ctru_sys::getThreadCommandBuffer();
    let cmdbuf = slice::from_raw_parts_mut(cmdbuf_ptr, 8);

    cmdbuf[0] = ctru_sys::IPC_MakeHeader(3, 0, 2); // 0x30002
    cmdbuf[1] = ctru_sys::IPC_Desc_StaticBuffer(std::mem::size_of_val(&args), 1);
    cmdbuf[2] = args.as_ptr() as u32;

    ctru_sys::R_SUCCEEDED(ctru_sys::svcSendSyncRequest(*handle.get_handle()))
}

struct LdrHandle {
    handle: ctru_sys::Handle,
}

impl LdrHandle {
    /// SAFETY: DO NOT EVER CALL THIS TWICE
    pub fn new() -> Option<LdrHandle> {
        let mut handle: MaybeUninit<ctru_sys::Handle> = MaybeUninit::uninit();
        unsafe {
            if !ctru_sys::R_SUCCEEDED(ctru_sys::svcConnectToPort(
                handle.as_mut_ptr(),
                b"hb:ldr".as_ptr(),
            )) {
                return None;
            }
        }

        let handle = unsafe { handle.assume_init() };

        Some(LdrHandle { handle })
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
