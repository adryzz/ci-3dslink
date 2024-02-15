use std::{
    fs::{File, OpenOptions},
    io,
};

pub fn log_file() -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .append(true)
        .open("ci-3dslink.log")
}
