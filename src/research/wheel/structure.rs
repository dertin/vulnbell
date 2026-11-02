use super::{MAX_BYTES, MAX_FILES, MAX_PATH_BYTES};
use anyhow::{Context, Result, bail};
use std::{
    collections::HashSet,
    io::{Read, Seek, SeekFrom},
};

const END_SIZE: usize = 22;
const CENTRAL_HEADER_SIZE: usize = 46;
const LOCAL_HEADER_SIZE: usize = 30;
const MAX_COMMENT: u64 = 65_535;
const MAX_EXTRA_BYTES: usize = 8 * 1024 * 1024;

/// Require an ordinary single-disk ZIP whose entry count covers its full central directory.
pub(super) fn validate(file: &mut std::fs::File) -> Result<()> {
    let size = file.metadata()?.len();
    if size < END_SIZE as u64 || size > MAX_BYTES {
        bail!("wheel archive exceeds its size limit or is truncated");
    }
    let tail_size = size.min(MAX_COMMENT + END_SIZE as u64);
    file.seek(SeekFrom::Start(size - tail_size))?;
    let mut tail = vec![0_u8; tail_size as usize];
    file.read_exact(&mut tail)?;
    let mut end = None;
    for index in 0..=tail.len() - END_SIZE {
        if &tail[index..index + 4] != b"PK\x05\x06" {
            continue;
        }
        let comment = u16_at(&tail[index..], 20) as usize;
        if index + END_SIZE + comment == tail.len() && end.replace(index).is_some() {
            bail!("wheel has ambiguous end records");
        }
    }
    let index = end.context("wheel end record is missing or invalid")?;
    let end = &tail[index..];
    let disk = u16_at(end, 4);
    let directory_disk = u16_at(end, 6);
    let disk_entries = u16_at(end, 8);
    let entries = u16_at(end, 10);
    let directory_size = u32_at(end, 12);
    let directory_offset = u32_at(end, 16);
    if disk != 0
        || directory_disk != 0
        || disk_entries != entries
        || entries == u16::MAX
        || directory_size == u32::MAX
        || directory_offset == u32::MAX
    {
        bail!("multi-disk and ZIP64 wheels are unsupported");
    }
    if entries == 0 || usize::from(entries) > MAX_FILES {
        bail!("wheel exceeds the entry limit or is empty");
    }
    let directory_start = u64::from(directory_offset);
    let directory_end = directory_start
        .checked_add(u64::from(directory_size))
        .context("wheel directory size overflow")?;
    let end_offset = size - tail_size + index as u64;
    if directory_end != end_offset {
        bail!("wheel central directory boundaries are inconsistent");
    }
    file.seek(SeekFrom::Start(directory_start))?;
    let mut offset = directory_start;
    let mut local_offsets = HashSet::new();
    let mut extra_bytes = 0_usize;
    for _ in 0..entries {
        let mut header = [0_u8; CENTRAL_HEADER_SIZE];
        if offset
            .checked_add(CENTRAL_HEADER_SIZE as u64)
            .is_none_or(|end| end > directory_end)
        {
            bail!("wheel central directory is truncated");
        }
        file.read_exact(&mut header)?;
        if &header[..4] != b"PK\x01\x02" {
            bail!("wheel central directory contains an invalid entry");
        }
        let name_len = usize::from(u16_at(&header, 28));
        let extra_len = usize::from(u16_at(&header, 30));
        let comment_len = usize::from(u16_at(&header, 32));
        if name_len > MAX_PATH_BYTES {
            bail!("wheel paths exceed the size limit");
        }
        let extra = (name_len + extra_len + comment_len) as u64;
        offset = offset
            .checked_add(CENTRAL_HEADER_SIZE as u64 + extra)
            .context("wheel directory entry overflow")?;
        if offset > directory_end {
            bail!("wheel central directory entry exceeds its boundary");
        }
        account_extra(&mut extra_bytes, extra_len)?;
        file.seek(SeekFrom::Current(name_len as i64))?;
        check_extra(file, extra_len)?;
        let local_offset = u64::from(u32_at(&header, 42));
        if !local_offsets.insert(local_offset) {
            bail!("wheel entries refer to a duplicate local header");
        }
        if local_offset
            .checked_add(LOCAL_HEADER_SIZE as u64)
            .is_none_or(|end| end > directory_start)
        {
            bail!("wheel local header is outside the data region");
        }
        file.seek(SeekFrom::Start(local_offset))?;
        let mut local = [0_u8; LOCAL_HEADER_SIZE];
        file.read_exact(&mut local)?;
        if &local[..4] != b"PK\x03\x04" {
            bail!("wheel local header is invalid");
        }
        let local_name_len = usize::from(u16_at(&local, 26));
        let local_extra_len = usize::from(u16_at(&local, 28));
        account_extra(&mut extra_bytes, local_extra_len)?;
        if local_name_len > MAX_PATH_BYTES
            || local_offset
                .checked_add((LOCAL_HEADER_SIZE + local_name_len + local_extra_len) as u64)
                .is_none_or(|end| end > directory_start)
        {
            bail!("wheel local header exceeds the data region");
        }
        file.seek(SeekFrom::Current(local_name_len as i64))?;
        check_extra(file, local_extra_len)?;
        file.seek(SeekFrom::Start(offset))?;
    }
    if offset != directory_end {
        bail!("wheel central directory count does not match its contents");
    }
    Ok(())
}

fn account_extra(total: &mut usize, length: usize) -> Result<()> {
    *total = total
        .checked_add(length)
        .context("wheel extra field size overflow")?;
    if *total > MAX_EXTRA_BYTES {
        bail!("wheel extra fields exceed the total size limit");
    }
    Ok(())
}

fn check_extra(file: &mut std::fs::File, length: usize) -> Result<()> {
    let mut extra = vec![0_u8; length];
    file.read_exact(&mut extra)?;
    let mut offset = 0;
    while offset < extra.len() {
        if extra.len() - offset < 4 {
            bail!("wheel extra field is truncated");
        }
        let id = u16_at(&extra, offset);
        let size = usize::from(u16_at(&extra, offset + 2));
        offset += 4;
        if size > extra.len() - offset {
            bail!("wheel extra field exceeds its boundary");
        }
        if id == 0x7075 {
            bail!("wheel has an ambiguous Unicode path field");
        }
        offset += size;
    }
    Ok(())
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

#[cfg(test)]
mod tests;
