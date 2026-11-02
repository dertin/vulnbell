use std::io::{Cursor, Seek, Write};

fn archive(comment: &str) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .start_file("example.py", zip::write::SimpleFileOptions::default())
        .unwrap();
    writer.write_all(b"synthetic").unwrap();
    writer.set_comment(comment).unwrap();
    writer.finish().unwrap().into_inner()
}

fn validate(bytes: &[u8]) -> anyhow::Result<()> {
    let mut file = tempfile::tempfile()?;
    file.write_all(bytes)?;
    file.rewind()?;
    super::validate(&mut file)
}

fn end_offset(bytes: &[u8]) -> usize {
    bytes
        .windows(4)
        .rposition(|window| window == b"PK\x05\x06")
        .unwrap()
}

#[test]
fn accepts_an_ordinary_archive_with_comment() {
    assert!(validate(&archive("synthetic comment")).is_ok());
}

#[test]
fn accepts_zip64_entry_headers_when_the_archive_directory_is_zip32() {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .start_file(
            "example.py",
            zip::write::SimpleFileOptions::default().large_file(true),
        )
        .unwrap();
    writer.write_all(b"synthetic").unwrap();
    let bytes = writer.finish().unwrap().into_inner();
    assert!(validate(&bytes).is_ok());
}

#[test]
fn rejects_ambiguous_end_records() {
    let mut bytes = archive("");
    let end = end_offset(&bytes);
    let duplicate = bytes[end..].to_vec();
    bytes[end + 20..end + 22].copy_from_slice(&(duplicate.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&duplicate);
    let error = validate(&bytes).unwrap_err();
    assert!(error.to_string().contains("ambiguous"));
}

#[test]
fn rejects_multidisk_and_zip64_end_records() {
    let mut multi = archive("");
    let end = end_offset(&multi);
    multi[end + 4..end + 6].copy_from_slice(&1_u16.to_le_bytes());
    assert!(
        validate(&multi)
            .unwrap_err()
            .to_string()
            .contains("multi-disk")
    );
    let mut zip64 = archive("");
    let end = end_offset(&zip64);
    zip64[end + 8..end + 10].copy_from_slice(&u16::MAX.to_le_bytes());
    zip64[end + 10..end + 12].copy_from_slice(&u16::MAX.to_le_bytes());
    assert!(validate(&zip64).unwrap_err().to_string().contains("ZIP64"));
}

#[test]
fn rejects_a_truncated_central_directory() {
    let mut bytes = archive("");
    let end = end_offset(&bytes);
    let size = u32::from_le_bytes(bytes[end + 12..end + 16].try_into().unwrap());
    bytes[end + 12..end + 16].copy_from_slice(&(size - 1).to_le_bytes());
    assert!(
        validate(&bytes)
            .unwrap_err()
            .to_string()
            .contains("boundaries")
    );
}

fn unicode_path_archive(central_only: bool) -> Vec<u8> {
    let mut options = zip::write::FullFileOptions::default();
    let mut extra = vec![1];
    extra.extend_from_slice(&0x72a1de33_u32.to_le_bytes());
    extra.extend_from_slice(b"example/safe.py");
    options
        .add_extra_field(0x7075, extra, central_only)
        .unwrap();
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    writer.start_file("example/_native.so", options).unwrap();
    writer.write_all(b"synthetic").unwrap();
    writer.finish().unwrap().into_inner()
}

#[test]
fn rejects_alternative_unicode_paths_in_central_and_local_headers() {
    for central_only in [true, false] {
        let bytes = unicode_path_archive(central_only);
        assert!(
            validate(&bytes)
                .unwrap_err()
                .to_string()
                .contains("ambiguous Unicode")
        );
    }
    let mut bytes = unicode_path_archive(false);
    let end = end_offset(&bytes);
    let central = u32::from_le_bytes(bytes[end + 16..end + 20].try_into().unwrap()) as usize;
    let name_len =
        u16::from_le_bytes(bytes[central + 28..central + 30].try_into().unwrap()) as usize;
    let extra = central + super::CENTRAL_HEADER_SIZE + name_len;
    assert_eq!(&bytes[extra..extra + 2], &[0x75, 0x70]);
    bytes[extra..extra + 2].copy_from_slice(&0xaaaa_u16.to_le_bytes());
    assert!(
        validate(&bytes)
            .unwrap_err()
            .to_string()
            .contains("ambiguous Unicode")
    );
}

#[test]
fn rejects_reused_local_header_offsets() {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for name in ["one.py", "two.py"] {
        writer
            .start_file(name, zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"synthetic").unwrap();
    }
    let mut bytes = writer.finish().unwrap().into_inner();
    let end = end_offset(&bytes);
    let first = u32::from_le_bytes(bytes[end + 16..end + 20].try_into().unwrap()) as usize;
    let name_len = u16::from_le_bytes(bytes[first + 28..first + 30].try_into().unwrap()) as usize;
    let extra_len = u16::from_le_bytes(bytes[first + 30..first + 32].try_into().unwrap()) as usize;
    let comment_len =
        u16::from_le_bytes(bytes[first + 32..first + 34].try_into().unwrap()) as usize;
    let second = first + super::CENTRAL_HEADER_SIZE + name_len + extra_len + comment_len;
    let first_offset = bytes[first + 42..first + 46].to_vec();
    bytes[second + 42..second + 46].copy_from_slice(&first_offset);
    assert!(
        validate(&bytes)
            .unwrap_err()
            .to_string()
            .contains("duplicate local header")
    );
}

#[test]
fn rejects_excessive_total_extra_fields() {
    let mut options = zip::write::FullFileOptions::default();
    let extra_size = 60_000;
    options
        .add_extra_field(0xfffe, vec![0_u8; extra_size], false)
        .unwrap();
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for index in 0..(super::MAX_EXTRA_BYTES / (extra_size * 2) + 2) {
        writer
            .start_file(format!("file-{index}"), options.clone())
            .unwrap();
    }
    let bytes = writer.finish().unwrap().into_inner();
    assert!(
        validate(&bytes)
            .unwrap_err()
            .to_string()
            .contains("extra fields exceed")
    );
}
