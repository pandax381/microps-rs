//! UDP protocol.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use spin::Mutex;

use crate::ip::{self, IpAddr, IpEndp, IpHdr, IpIface, IP_PROTOCOL_UDP};
use crate::platform::task::{self, Task, WaitResult};
use crate::util;

pub const UDP_HDR_SIZE: usize = 8;
const UDP_PSEUDO_HDR_SIZE: usize = 12;

pub const PCB_SIZE_MAX: usize = 16;

const DYNAMIC_PORT_MIN: u16 = 49152;
const DYNAMIC_PORT_MAX: u16 = 65535;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvError {
    NotBound,
    Interrupted,
}

fn build_pseudo_header(src: IpAddr, dst: IpAddr, udp_len: u16) -> [u8; UDP_PSEUDO_HDR_SIZE] {
    let mut buf = [0u8; UDP_PSEUDO_HDR_SIZE];
    buf[0..4].copy_from_slice(&src.0);
    buf[4..8].copy_from_slice(&dst.0);
    buf[9] = IP_PROTOCOL_UDP;
    buf[10..12].copy_from_slice(&udp_len.to_be_bytes());
    buf
}

pub struct UdpHdr<'a> {
    data: &'a [u8],
}

impl<'a> UdpHdr<'a> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < UDP_HDR_SIZE {
            return None;
        }
        Some(Self { data })
    }

    pub fn src(&self) -> u16 {
        u16::from_be_bytes([self.data[0], self.data[1]])
    }

    pub fn dst(&self) -> u16 {
        u16::from_be_bytes([self.data[2], self.data[3]])
    }

    pub fn len(&self) -> u16 {
        u16::from_be_bytes([self.data[4], self.data[5]])
    }

    pub fn sum(&self) -> u16 {
        u16::from_be_bytes([self.data[6], self.data[7]])
    }
}

#[allow(dead_code)]
struct UdpQueueEntry {
    remote: IpEndp,
    data: Vec<u8>,
}

struct UdpPcb {
    local: IpEndp,
    queue: VecDeque<UdpQueueEntry>,
    task: Arc<Task>,
}

impl UdpPcb {
    fn empty() -> Self {
        Self {
            local: IpEndp::new(IpAddr::ANY, 0),
            queue: VecDeque::new(),
            task: task::new_task(),
        }
    }
}

static PCBS: Mutex<Vec<Option<UdpPcb>>> = Mutex::new(Vec::new());

pub type UdpDesc = usize;

fn pcb_alloc(pcbs: &mut Vec<Option<UdpPcb>>) -> Option<UdpDesc> {
    for (i, slot) in pcbs.iter_mut().enumerate() {
        if slot.is_none() {
            *slot = Some(UdpPcb::empty());
            return Some(i);
        }
    }
    if pcbs.len() >= PCB_SIZE_MAX {
        return None;
    }
    let desc = pcbs.len();
    pcbs.push(Some(UdpPcb::empty()));
    Some(desc)
}

fn pcb_release(pcbs: &mut [Option<UdpPcb>], desc: UdpDesc) -> Result<(), ()> {
    let pcb = pcb_get_mut(pcbs, desc).ok_or(())?;
    let task = pcb.task.clone();
    *pcbs.get_mut(desc).unwrap() = None;
    task.notify();
    Ok(())
}

fn pcb_get_mut<'a>(
    pcbs: &'a mut [Option<UdpPcb>],
    desc: UdpDesc,
) -> Option<&'a mut UdpPcb> {
    pcbs.get_mut(desc).and_then(|s| s.as_mut())
}

fn pcb_select(pcbs: &[Option<UdpPcb>], key: IpEndp) -> Option<UdpDesc> {
    pcbs.iter().enumerate().find_map(|(i, slot)| {
        let pcb = slot.as_ref()?;
        let matched = pcb.local.port == key.port
            && (pcb.local.addr == key.addr
                || pcb.local.addr == IpAddr::ANY
                || key.addr == IpAddr::ANY);
        matched.then_some(i)
    })
}

pub fn open() -> Option<UdpDesc> {
    let mut pcbs = PCBS.lock();
    let desc = pcb_alloc(&mut pcbs)?;
    crate::debugf!("desc={}", desc);
    Some(desc)
}

pub fn close(desc: UdpDesc) -> Result<(), ()> {
    let mut pcbs = PCBS.lock();
    pcb_release(&mut pcbs, desc).map_err(|_| {
        crate::errorf!("pcb not found, desc={}", desc);
    })?;
    crate::debugf!("desc={}", desc);
    Ok(())
}

pub fn bind(desc: UdpDesc, local: IpEndp) -> Result<(), ()> {
    let mut pcbs = PCBS.lock();
    if pcb_get_mut(&mut pcbs, desc).is_none() {
        crate::errorf!("pcb not found, desc={}", desc);
        return Err(());
    }
    if let Some(exist_desc) = pcb_select(&pcbs, local) {
        let exist_local = pcbs[exist_desc].as_ref().unwrap().local;
        crate::errorf!(
            "already in use, desc={}, want={}, exist={}",
            desc,
            local,
            exist_local
        );
        return Err(());
    }
    let pcb = pcb_get_mut(&mut pcbs, desc).unwrap();
    pcb.local = local;
    crate::debugf!("desc={}, {}", desc, local);
    Ok(())
}

fn print(data: &[u8]) {
    if let Some(hdr) = UdpHdr::new(data) {
        crate::printf!("        src: {}", hdr.src());
        crate::printf!("        dst: {}", hdr.dst());
        crate::printf!("        len: {}", hdr.len());
        crate::printf!("        sum: 0x{:04x}", hdr.sum());
    }
    crate::printf!("{}", crate::util::HexDump(data));
}

fn input(hdr: &IpHdr<'_>, data: &[u8], iface: &IpIface) {
    if data.len() < UDP_HDR_SIZE {
        crate::errorf!("too short, len={}", data.len());
        return;
    }
    let udp = match UdpHdr::new(data) {
        Some(u) => u,
        None => return,
    };
    if (udp.len() as usize) != data.len() {
        crate::errorf!(
            "length mismatch, header={}, actual={}",
            udp.len(),
            data.len()
        );
        return;
    }
    if udp.sum() != 0 {
        let pseudo = build_pseudo_header(hdr.src(), hdr.dst(), data.len() as u16);
        let init = !util::cksum16(&pseudo, 0) as u32;
        if util::cksum16(data, init) != 0 {
            crate::errorf!("checksum error, sum=0x{:04x}", udp.sum());
            return;
        }
    }
    let src = IpEndp::new(hdr.src(), udp.src());
    let dst = IpEndp::new(hdr.dst(), udp.dst());
    crate::debugf!(
        "{} => {}, dev={}, len={}",
        src,
        dst,
        iface.dev().name,
        data.len()
    );
    print(data);

    let mut pcbs = PCBS.lock();
    let Some(desc) = pcb_select(&pcbs, dst) else {
        drop(pcbs);
        // Only send ICMP Port Unreachable for unicast destinations.
        if hdr.dst() == iface.unicast() {
            let mut buf = Vec::with_capacity(hdr.as_bytes().len() + 8);
            buf.extend_from_slice(hdr.as_bytes());
            buf.extend_from_slice(&data[..data.len().min(8)]);
            let _ = crate::icmp::output(
                crate::icmp::ICMP_TYPE_DEST_UNREACH,
                crate::icmp::ICMP_CODE_PORT_UNREACH,
                0,
                &buf,
                iface.unicast(),
                hdr.src(),
            );
        }
        return;
    };
    let payload = data[UDP_HDR_SIZE..].to_vec();
    if let Some(pcb) = pcb_get_mut(&mut pcbs, desc) {
        pcb.queue.push_back(UdpQueueEntry {
            remote: src,
            data: payload,
        });
        crate::debugf!(
            "queue push: desc={}, remote={}, num={}",
            desc,
            src,
            pcb.queue.len()
        );
        let task = pcb.task.clone();
        drop(pcbs);
        task.notify();
    }
}

pub fn recvfrom(desc: UdpDesc, buf: &mut [u8]) -> Result<(IpEndp, usize), RecvError> {
    loop {
        let (task, snapshot) = {
            let mut pcbs = PCBS.lock();
            let pcb = pcb_get_mut(&mut pcbs, desc).ok_or_else(|| {
                crate::errorf!("pcb not found, desc={}", desc);
                RecvError::NotBound
            })?;
            if let Some(entry) = pcb.queue.pop_front() {
                let n = buf.len().min(entry.data.len());
                buf[..n].copy_from_slice(&entry.data[..n]);
                crate::debugf!(
                    "queue pop: desc={}, remote={}, len={}",
                    desc,
                    entry.remote,
                    n
                );
                return Ok((entry.remote, n));
            }
            (pcb.task.clone(), pcb.task.snapshot())
        };
        match task.wait_after(snapshot) {
            WaitResult::Notified => continue,
            WaitResult::Interrupted => return Err(RecvError::Interrupted),
        }
    }
}

fn assign_dynamic_port(
    pcbs: &mut Vec<Option<UdpPcb>>,
    desc: UdpDesc,
    local_addr: IpAddr,
) -> Result<u16, ()> {
    for port in DYNAMIC_PORT_MIN..=DYNAMIC_PORT_MAX {
        if pcb_select(pcbs, IpEndp::new(local_addr, port)).is_none() {
            pcbs[desc].as_mut().unwrap().local.port = port;
            return Ok(port);
        }
    }
    crate::errorf!("no dynamic port available");
    Err(())
}

fn output(src: IpEndp, dst: IpEndp, data: &[u8]) -> Result<usize, ()> {
    let total = UDP_HDR_SIZE + data.len();
    if total > u16::MAX as usize {
        crate::errorf!("too long, len={}", total);
        return Err(());
    }
    let mut buf = vec![0u8; total];
    buf[0..2].copy_from_slice(&src.port.to_be_bytes());
    buf[2..4].copy_from_slice(&dst.port.to_be_bytes());
    buf[4..6].copy_from_slice(&(total as u16).to_be_bytes());
    buf[UDP_HDR_SIZE..].copy_from_slice(data);

    let pseudo = build_pseudo_header(src.addr, dst.addr, total as u16);
    let init = !util::cksum16(&pseudo, 0) as u32;
    let sum = util::cksum16(&buf, init);
    let sum = if sum == 0 { 0xffff } else { sum };
    buf[6..8].copy_from_slice(&sum.to_ne_bytes());

    crate::debugf!("{} => {}, len={}", src, dst, total);
    print(&buf);

    ip::output(IP_PROTOCOL_UDP, &buf, src.addr, dst.addr)?;
    Ok(data.len())
}

pub fn sendto(desc: UdpDesc, data: &[u8], remote: IpEndp) -> Result<usize, ()> {
    let local = {
        let mut pcbs = PCBS.lock();
        if pcb_get_mut(&mut pcbs, desc).is_none() {
            crate::errorf!("pcb not found, desc={}", desc);
            return Err(());
        }
        let local_addr = pcbs[desc].as_ref().unwrap().local.addr;
        let local_port = pcbs[desc].as_ref().unwrap().local.port;
        let port = if local_port == 0 {
            assign_dynamic_port(&mut pcbs, desc, local_addr)?
        } else {
            local_port
        };
        IpEndp::new(local_addr, port)
    };

    let src_addr = if local.addr == IpAddr::ANY {
        let route = ip::route_lookup(remote.addr).ok_or_else(|| {
            crate::errorf!("no route to {}", remote.addr);
        })?;
        route.iface.unicast()
    } else {
        local.addr
    };

    output(IpEndp::new(src_addr, local.port), remote, data)
}

pub fn init() -> Result<(), ()> {
    ip::register_protocol(IP_PROTOCOL_UDP, input)?;
    Ok(())
}
