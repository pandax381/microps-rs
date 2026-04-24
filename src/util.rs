//! Utility functions.

use alloc::string::String;
use core::fmt::{self, Write as _};

/// Internet checksum (RFC 1071).
pub fn cksum16(data: &[u8], init: u32) -> u16 {
    let mut sum = init;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_ne_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += data[i] as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Hex dump formatter.
pub struct HexDump<'a>(pub &'a [u8]);

impl fmt::Display for HexDump<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let data = self.0;
        f.write_str(
            "+------+-------------------------------------------------+------------------+\n",
        )?;
        let mut line = String::with_capacity(80);
        for (offset, chunk) in data.chunks(16).enumerate() {
            line.clear();
            write!(&mut line, "| {:04x} | ", offset * 16).unwrap();
            for i in 0..16 {
                if i < chunk.len() {
                    write!(&mut line, "{:02x} ", chunk[i]).unwrap();
                } else {
                    line.push_str("   ");
                }
            }
            line.push_str("| ");
            for i in 0..16 {
                if i < chunk.len() {
                    let b = chunk[i];
                    if b.is_ascii_graphic() || b == b' ' {
                        line.push(b as char);
                    } else {
                        line.push('.');
                    }
                } else {
                    line.push(' ');
                }
            }
            line.push_str(" |\n");
            f.write_str(&line)?;
        }
        f.write_str(
            "+------+-------------------------------------------------+------------------+",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_DATA: &[u8] = &[
        0x45, 0x00, 0x00, 0x30, 0x00, 0x80, 0x00, 0x00, 0xff, 0x01, 0xbd, 0x4a, 0x7f, 0x00, 0x00,
        0x01, 0x7f, 0x00, 0x00, 0x01, 0x08, 0x00, 0x35, 0x64, 0x00, 0x80, 0x00, 0x01, 0x31, 0x32,
        0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x21, 0x40, 0x23, 0x24, 0x25, 0x5e, 0x26,
        0x2a, 0x28, 0x29,
    ];

    #[test]
    fn verify_ip_header_checksum() {
        let ip_header = &TEST_DATA[..20];
        assert_eq!(cksum16(ip_header, 0), 0);
    }

    #[test]
    fn verify_icmp_checksum() {
        let icmp_message = &TEST_DATA[20..];
        assert_eq!(cksum16(icmp_message, 0), 0);
    }

    #[test]
    fn compute_checksum() {
        let mut ip_header = [0u8; 20];
        ip_header.copy_from_slice(&TEST_DATA[..20]);
        ip_header[10] = 0;
        ip_header[11] = 0;
        let checksum = cksum16(&ip_header, 0);
        let original = u16::from_ne_bytes([TEST_DATA[10], TEST_DATA[11]]);
        assert_eq!(checksum, original);
    }

    #[test]
    fn checksum_empty() {
        assert_eq!(cksum16(&[], 0), 0xffff);
    }

    #[test]
    fn checksum_single_byte() {
        let data = [0x01];
        let result = cksum16(&data, 0);
        assert_eq!(result, !0x0001u16);
    }

    #[test]
    fn checksum_with_init() {
        let part1 = &TEST_DATA[..10];
        let part2 = &TEST_DATA[10..20];
        let partial = cksum16(part1, 0);
        let init = !partial as u32;
        let combined = cksum16(part2, init);
        let whole = cksum16(&TEST_DATA[..20], 0);
        assert_eq!(combined, whole);
    }

    #[test]
    fn hexdump_format() {
        let data = [0x45u8, 0x00, 0x00, 0x30];
        let output = alloc::format!("{}", HexDump(&data));
        assert!(output.contains("0000"));
        assert!(output.contains("45 00 00 30"));
        assert!(output.contains("E..0"));
    }

    #[test]
    fn hexdump_multiline() {
        let output = alloc::format!("{}", HexDump(TEST_DATA));
        assert!(output.contains("0000"));
        assert!(output.contains("0010"));
        assert!(output.contains("0020"));
        assert!(output.contains("1234"));
    }

    #[test]
    fn hexdump_empty() {
        let output = alloc::format!("{}", HexDump(&[]));
        assert!(output.contains("+------+"));
        assert!(!output.contains("0000"));
    }
}
