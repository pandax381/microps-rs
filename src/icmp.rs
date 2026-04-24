//! ICMP protocol.

use crate::ip::{self, IpHdr, IpIface, IP_PROTOCOL_ICMP};
use crate::util;

pub const ICMP_HDR_SIZE: usize = 8;

pub const ICMP_TYPE_ECHO_REPLY: u8 = 0;
pub const ICMP_TYPE_DEST_UNREACH: u8 = 3;
pub const ICMP_TYPE_SOURCE_QUENCH: u8 = 4;
pub const ICMP_TYPE_REDIRECT: u8 = 5;
pub const ICMP_TYPE_ECHO: u8 = 8;
pub const ICMP_TYPE_TIME_EXCEEDED: u8 = 11;
pub const ICMP_TYPE_PARAM_PROBLEM: u8 = 12;
pub const ICMP_TYPE_TIMESTAMP: u8 = 13;
pub const ICMP_TYPE_TIMESTAMP_REPLY: u8 = 14;
pub const ICMP_TYPE_INFO_REQUEST: u8 = 15;
pub const ICMP_TYPE_INFO_REPLY: u8 = 16;

pub struct IcmpCommon<'a> {
    data: &'a [u8],
}

impl<'a> IcmpCommon<'a> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < ICMP_HDR_SIZE {
            return None;
        }
        Some(Self { data })
    }

    pub fn ty(&self) -> u8 {
        self.data[0]
    }

    pub fn code(&self) -> u8 {
        self.data[1]
    }

    pub fn sum(&self) -> u16 {
        u16::from_be_bytes([self.data[2], self.data[3]])
    }

    pub fn dep(&self) -> u32 {
        u32::from_be_bytes([self.data[4], self.data[5], self.data[6], self.data[7]])
    }
}

pub struct IcmpEcho<'a> {
    data: &'a [u8],
}

impl<'a> IcmpEcho<'a> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < ICMP_HDR_SIZE {
            return None;
        }
        Some(Self { data })
    }

    pub fn common(&self) -> IcmpCommon<'_> {
        IcmpCommon { data: self.data }
    }

    pub fn id(&self) -> u16 {
        u16::from_be_bytes([self.data[4], self.data[5]])
    }

    pub fn seq(&self) -> u16 {
        u16::from_be_bytes([self.data[6], self.data[7]])
    }
}

pub struct IcmpDestUnreach<'a> {
    data: &'a [u8],
}

impl<'a> IcmpDestUnreach<'a> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < ICMP_HDR_SIZE {
            return None;
        }
        Some(Self { data })
    }

    pub fn common(&self) -> IcmpCommon<'_> {
        IcmpCommon { data: self.data }
    }
}

fn type_name(ty: u8) -> &'static str {
    match ty {
        ICMP_TYPE_ECHO_REPLY => "EchoReply",
        ICMP_TYPE_DEST_UNREACH => "DestinationUnreachable",
        ICMP_TYPE_SOURCE_QUENCH => "SourceQuench",
        ICMP_TYPE_REDIRECT => "Redirect",
        ICMP_TYPE_ECHO => "Echo",
        ICMP_TYPE_TIME_EXCEEDED => "TimeExceeded",
        ICMP_TYPE_PARAM_PROBLEM => "ParameterProblem",
        ICMP_TYPE_TIMESTAMP => "Timestamp",
        ICMP_TYPE_TIMESTAMP_REPLY => "TimestampReply",
        ICMP_TYPE_INFO_REQUEST => "InformationRequest",
        ICMP_TYPE_INFO_REPLY => "InformationReply",
        _ => "Unknown",
    }
}

fn print(data: &[u8]) {
    if let Some(com) = IcmpCommon::new(data) {
        crate::printf!("       type: {} ({})", com.ty(), type_name(com.ty()));
        crate::printf!("       code: {}", com.code());
        crate::printf!("        sum: 0x{:04x}", com.sum());
        match com.ty() {
            ICMP_TYPE_ECHO | ICMP_TYPE_ECHO_REPLY => {
                if let Some(echo) = IcmpEcho::new(data) {
                    crate::printf!("         id: {}", echo.id());
                    crate::printf!("        seq: {}", echo.seq());
                }
            }
            _ => {}
        }
    }
    crate::printf!("{}", crate::util::HexDump(data));
}

fn input(hdr: &IpHdr<'_>, data: &[u8], iface: &IpIface) {
    crate::debugf!(
        "{} => {}, dev={}, len={}",
        hdr.src(),
        hdr.dst(),
        iface.dev().name,
        data.len()
    );
    if data.len() < ICMP_HDR_SIZE {
        crate::errorf!("too short, len={}", data.len());
        return;
    }
    if util::cksum16(data, 0) != 0 {
        let com = IcmpCommon::new(data).unwrap();
        crate::errorf!("checksum error, sum=0x{:04x}", com.sum());
        return;
    }
    print(data);
}

pub fn init() -> Result<(), ()> {
    ip::register_protocol(IP_PROTOCOL_ICMP, input)?;
    Ok(())
}
