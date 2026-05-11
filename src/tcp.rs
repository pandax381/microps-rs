//! TCP protocol.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::time::Duration;

use spin::Mutex;

use crate::ip::{self, IpAddr, IpEndp, IpHdr, IpIface, IP_HDR_SIZE_MIN, IP_PROTOCOL_TCP};
use crate::platform::task::{self, Task, WaitResult};
use crate::util;

pub const TCP_HDR_SIZE: usize = 20;
const TCP_PSEUDO_HDR_SIZE: usize = 12;

pub const TCP_FLG_FIN: u8 = 0x01;
pub const TCP_FLG_SYN: u8 = 0x02;
pub const TCP_FLG_RST: u8 = 0x04;
pub const TCP_FLG_PSH: u8 = 0x08;
pub const TCP_FLG_ACK: u8 = 0x10;
pub const TCP_FLG_URG: u8 = 0x20;

pub const PCB_SIZE_MAX: usize = 16;
const RECV_BUF_SIZE: usize = 65535;
const TCP_DEFAULT_RTO: Duration = Duration::from_micros(200_000);
const TCP_RETRANS_DEADLINE: Duration = Duration::from_secs(12);
const TCP_TIMEWAIT_SEC: Duration = Duration::from_secs(30);
const TCP_TIMER_INTERVAL: Duration = Duration::from_millis(100);
const DYNAMIC_PORT_MIN: u16 = 49152;
const DYNAMIC_PORT_MAX: u16 = 65535;

pub type TcpDesc = usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

impl fmt::Display for TcpState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TcpState::Closed => "CLOSED",
            TcpState::Listen => "LISTEN",
            TcpState::SynSent => "SYN_SENT",
            TcpState::SynReceived => "SYN_RECEIVED",
            TcpState::Established => "ESTABLISHED",
            TcpState::FinWait1 => "FIN_WAIT1",
            TcpState::FinWait2 => "FIN_WAIT2",
            TcpState::CloseWait => "CLOSE_WAIT",
            TcpState::Closing => "CLOSING",
            TcpState::LastAck => "LAST_ACK",
            TcpState::TimeWait => "TIME_WAIT",
        })
    }
}

fn flag_isset(flg: u8, mask: u8) -> bool {
    (flg & 0x3f) & mask != 0
}

fn build_pseudo_header(src: IpAddr, dst: IpAddr, tcp_len: u16) -> [u8; TCP_PSEUDO_HDR_SIZE] {
    let mut buf = [0u8; TCP_PSEUDO_HDR_SIZE];
    buf[0..4].copy_from_slice(&src.0);
    buf[4..8].copy_from_slice(&dst.0);
    buf[9] = IP_PROTOCOL_TCP;
    buf[10..12].copy_from_slice(&tcp_len.to_be_bytes());
    buf
}

pub struct TcpHdr<'a> {
    data: &'a [u8],
}

impl<'a> TcpHdr<'a> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < TCP_HDR_SIZE {
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

    pub fn seq(&self) -> u32 {
        u32::from_be_bytes([self.data[4], self.data[5], self.data[6], self.data[7]])
    }

    pub fn ack(&self) -> u32 {
        u32::from_be_bytes([self.data[8], self.data[9], self.data[10], self.data[11]])
    }

    pub fn off(&self) -> u8 {
        self.data[12]
    }

    pub fn hlen(&self) -> usize {
        ((self.off() >> 4) as usize) * 4
    }

    pub fn flg(&self) -> u8 {
        self.data[13]
    }

    pub fn wnd(&self) -> u16 {
        u16::from_be_bytes([self.data[14], self.data[15]])
    }

    pub fn sum(&self) -> u16 {
        u16::from_be_bytes([self.data[16], self.data[17]])
    }

    pub fn up(&self) -> u16 {
        u16::from_be_bytes([self.data[18], self.data[19]])
    }
}

fn flag_char(flg: u8, mask: u8, c: char) -> char {
    if flag_isset(flg, mask) { c } else { '-' }
}

struct FlagStr(u8);

impl core::fmt::Display for FlagStr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let flg = self.0;
        write!(
            f,
            "--{}{}{}{}{}{}",
            flag_char(flg, TCP_FLG_URG, 'U'),
            flag_char(flg, TCP_FLG_ACK, 'A'),
            flag_char(flg, TCP_FLG_PSH, 'P'),
            flag_char(flg, TCP_FLG_RST, 'R'),
            flag_char(flg, TCP_FLG_SYN, 'S'),
            flag_char(flg, TCP_FLG_FIN, 'F'),
        )
    }
}

fn option_name(kind: u8) -> &'static str {
    match kind {
        0 => "End of Option List (EOL)",
        1 => "No-Operation (NOP)",
        2 => "Maximum Segment Size (MSS)",
        3 => "Window Scale",
        4 => "SACK Permitted",
        5 => "SACK",
        8 => "Timestamps",
        _ => "Unknown",
    }
}

fn print(data: &[u8]) {
    let Some(hdr) = TcpHdr::new(data) else { return };
    let hlen = hdr.hlen();
    crate::printf!("        src: {}", hdr.src());
    crate::printf!("        dst: {}", hdr.dst());
    crate::printf!("        seq: {}", hdr.seq());
    crate::printf!("        ack: {}", hdr.ack());
    crate::printf!(
        "        off: 0x{:02x} ({}) (options: {}, payload: {})",
        hdr.off(),
        hlen,
        hlen - TCP_HDR_SIZE,
        data.len() - hlen,
    );
    crate::printf!("        flg: 0x{:02x} ({})", hdr.flg(), FlagStr(hdr.flg()));
    crate::printf!("        wnd: {}", hdr.wnd());
    crate::printf!("        sum: 0x{:04x}", hdr.sum());
    crate::printf!("         up: {}", hdr.up());

    let mut i = 0;
    let mut pos = TCP_HDR_SIZE;
    while pos < hlen {
        let kind = data[pos];
        if kind == 0 {
            crate::printf!("     opt[{}]: kind={} ({})", i, kind, option_name(kind));
            break;
        }
        if kind == 1 {
            crate::printf!("     opt[{}]: kind={} ({})", i, kind, option_name(kind));
            pos += 1;
        } else {
            if pos + 1 >= hlen {
                break;
            }
            let olen = data[pos + 1] as usize;
            crate::printf!(
                "     opt[{}]: kind={} ({}), len={}",
                i,
                kind,
                option_name(kind),
                olen,
            );
            if olen == 0 {
                break;
            }
            pos += olen;
        }
        i += 1;
    }
    crate::printf!("{}", util::HexDump(data));
}

#[allow(dead_code)]
#[derive(Default)]
struct SndVars {
    nxt: u32,
    una: u32,
    wnd: u16,
    up: u16,
    wl1: u32,
    wl2: u32,
}

#[allow(dead_code)]
#[derive(Default)]
struct RcvVars {
    nxt: u32,
    wnd: u16,
    up: u16,
}

#[allow(dead_code)]
struct SegInfo {
    seq: u32,
    ack: u32,
    len: u32,
    wnd: u16,
    up: u16,
}

struct TcpQueueEntry {
    first: Duration,
    last: Duration,
    rto: Duration,
    seq: u32,
    flg: u8,
    data: Vec<u8>,
}

#[allow(dead_code)]
struct TcpPcb {
    state: TcpState,
    local: IpEndp,
    remote: IpEndp,
    snd: SndVars,
    iss: u32,
    rcv: RcvVars,
    irs: u32,
    mss: u16,
    buf: Vec<u8>,
    queue: VecDeque<TcpQueueEntry>,
    tw_timer: Duration,
    task: Arc<Task>,
}

impl TcpPcb {
    fn empty() -> Self {
        Self {
            state: TcpState::Closed,
            local: IpEndp::new(IpAddr::ANY, 0),
            remote: IpEndp::new(IpAddr::ANY, 0),
            snd: SndVars::default(),
            iss: 0,
            rcv: RcvVars::default(),
            irs: 0,
            mss: 0,
            buf: Vec::new(),
            queue: VecDeque::new(),
            tw_timer: Duration::ZERO,
            task: task::new_task(),
        }
    }
}

static PCBS: Mutex<Vec<Option<TcpPcb>>> = Mutex::new(Vec::new());

fn pcb_alloc(pcbs: &mut Vec<Option<TcpPcb>>) -> Option<usize> {
    for (i, slot) in pcbs.iter_mut().enumerate() {
        if slot.is_none() {
            *slot = Some(TcpPcb::empty());
            return Some(i);
        }
    }
    if pcbs.len() >= PCB_SIZE_MAX {
        return None;
    }
    let desc = pcbs.len();
    pcbs.push(Some(TcpPcb::empty()));
    Some(desc)
}

fn pcb_release(pcbs: &mut [Option<TcpPcb>], desc: usize) -> Result<(), ()> {
    let pcb = pcbs.get_mut(desc).and_then(|s| s.as_mut()).ok_or(())?;
    let task = pcb.task.clone();
    *pcbs.get_mut(desc).unwrap() = None;
    task.notify();
    Ok(())
}

fn pcb_get_mut<'a>(
    pcbs: &'a mut [Option<TcpPcb>],
    desc: usize,
) -> Option<&'a mut TcpPcb> {
    pcbs.get_mut(desc).and_then(|s| s.as_mut())
}

fn transition(pcb: &mut TcpPcb, desc: TcpDesc, new_state: TcpState) {
    crate::debugf!("desc={}, {} => {}", desc, pcb.state, new_state);
    pcb.state = new_state;
}

fn output(pcb: &mut TcpPcb, flg: u8, data: &[u8]) -> Result<usize, ()> {
    let seq = if flag_isset(flg, TCP_FLG_SYN) {
        pcb.iss
    } else {
        pcb.snd.nxt
    };
    if flag_isset(flg, TCP_FLG_SYN | TCP_FLG_FIN) || !data.is_empty() {
        retrans_queue_add(pcb, seq, flg, data);
    }
    output_segment(seq, pcb.rcv.nxt, flg, pcb.rcv.wnd, data, pcb.local, pcb.remote)
}

fn retrans_queue_add(pcb: &mut TcpPcb, seq: u32, flg: u8, data: &[u8]) {
    let now = crate::time::now();
    pcb.queue.push_back(TcpQueueEntry {
        first: now,
        last: now,
        rto: TCP_DEFAULT_RTO,
        seq,
        flg,
        data: data.to_vec(),
    });
    crate::debugf!("num={}, seq={}", pcb.queue.len(), seq);
}

fn retrans_queue_cleanup(pcb: &mut TcpPcb) {
    while let Some(entry) = pcb.queue.front() {
        let mut consume = entry.data.len() as u32;
        if flag_isset(entry.flg, TCP_FLG_SYN | TCP_FLG_FIN) {
            consume += 1;
        }
        if pcb.snd.una < entry.seq.wrapping_add(consume) {
            break;
        }
        let popped = pcb.queue.pop_front().unwrap();
        crate::debugf!("num={}, seq={}", pcb.queue.len(), popped.seq);
    }
}

fn retrans_emit(pcbs: &mut [Option<TcpPcb>], desc: usize) {
    let now = crate::time::now();

    let deadline_exceeded = {
        let Some(pcb) = pcbs[desc].as_ref() else { return };
        pcb.queue
            .iter()
            .any(|e| now >= e.first + TCP_RETRANS_DEADLINE)
    };
    if deadline_exceeded {
        let pcb = pcbs[desc].as_mut().unwrap();
        let task = pcb.task.clone();
        transition(pcb, desc, TcpState::Closed);
        task.notify();
        return;
    }

    let pcb = pcbs[desc].as_mut().unwrap();
    let local = pcb.local;
    let remote = pcb.remote;
    let rcv_nxt = pcb.rcv.nxt;
    let rcv_wnd = pcb.rcv.wnd;
    for entry in pcb.queue.iter_mut() {
        if now >= entry.last + entry.rto {
            crate::debugf!("desc={}, seq={}", desc, entry.seq);
            let _ = output_segment(
                entry.seq, rcv_nxt, entry.flg, rcv_wnd, &entry.data, local, remote,
            );
            entry.last = now;
            entry.rto *= 2;
        }
    }
}

fn set_timewait_timer(pcb: &mut TcpPcb) {
    pcb.tw_timer = crate::time::now() + TCP_TIMEWAIT_SEC;
    crate::debugf!("start time_wait timer: {} seconds", TCP_TIMEWAIT_SEC.as_secs());
}

fn on_timer() {
    let mut pcbs = PCBS.lock();
    let now = crate::time::now();
    let len = pcbs.len();
    for desc in 0..len {
        if pcbs[desc].is_none() {
            continue;
        }
        let state = pcbs[desc].as_ref().unwrap().state;
        if state == TcpState::TimeWait {
            let tw_timer = pcbs[desc].as_ref().unwrap().tw_timer;
            if now > tw_timer {
                crate::debugf!("timewait has elapsed, desc={}", desc);
                let pcb = pcbs[desc].as_mut().unwrap();
                transition(pcb, desc, TcpState::Closed);
                let _ = pcb_release(&mut pcbs, desc);
                continue;
            }
        }
        retrans_emit(&mut pcbs, desc);
    }
}

fn pcb_select(pcbs: &[Option<TcpPcb>], local: IpEndp, remote: IpEndp) -> Option<usize> {
    let mut candidate: Option<usize> = None;
    for (i, slot) in pcbs.iter().enumerate() {
        let Some(pcb) = slot.as_ref() else { continue };
        if pcb.local.port != local.port {
            continue;
        }
        let local_match = pcb.local.addr == local.addr
            || pcb.local.addr == IpAddr::ANY
            || local.addr != IpAddr::ANY;
        if !local_match {
            continue;
        }
        let remote_match = (pcb.remote.addr == remote.addr && pcb.remote.port == remote.port)
            || (pcb.remote.addr == IpAddr::ANY && pcb.remote.port == 0)
            || (remote.addr == IpAddr::ANY && remote.port == 0);
        if !remote_match {
            continue;
        }
        if pcb.state != TcpState::Listen {
            return Some(i);
        }
        candidate = Some(i);
    }
    candidate
}

fn output_segment(
    seq: u32,
    ack: u32,
    flg: u8,
    wnd: u16,
    data: &[u8],
    local: IpEndp,
    remote: IpEndp,
) -> Result<usize, ()> {
    let hlen = TCP_HDR_SIZE;
    let total = hlen + data.len();
    let mut buf = vec![0u8; total];

    buf[0..2].copy_from_slice(&local.port.to_be_bytes());
    buf[2..4].copy_from_slice(&remote.port.to_be_bytes());
    buf[4..8].copy_from_slice(&seq.to_be_bytes());
    buf[8..12].copy_from_slice(&ack.to_be_bytes());
    buf[12] = ((hlen / 4) as u8) << 4;
    buf[13] = flg;
    buf[14..16].copy_from_slice(&wnd.to_be_bytes());
    // sum (16..18) and up (18..20) are zero
    buf[hlen..].copy_from_slice(data);

    let pseudo = build_pseudo_header(local.addr, remote.addr, total as u16);
    let init = !util::cksum16(&pseudo, 0) as u32;
    let sum = util::cksum16(&buf, init);
    buf[16..18].copy_from_slice(&sum.to_ne_bytes());

    crate::debugf!("{} => {}, len={}", local, remote, total);
    print(&buf);

    ip::output(IP_PROTOCOL_TCP, &buf, local.addr, remote.addr)?;
    Ok(data.len())
}

/// RFC793 section 3.9 [Event Processing > SEGMENT ARRIVES]
fn segment_arrives(
    pcbs: &mut Vec<Option<TcpPcb>>,
    seg: &SegInfo,
    flags: u8,
    data: &[u8],
    local: IpEndp,
    remote: IpEndp,
) {
    let pcb_desc = pcb_select(pcbs, local, remote);

    // CLOSED state (or no PCB)
    let is_closed = match pcb_desc {
        Some(desc) => pcbs[desc].as_ref().unwrap().state == TcpState::Closed,
        None => true,
    };
    if is_closed {
        crate::debugf!(
            "PCB is {}",
            if pcb_desc.is_some() { "closed" } else { "not found" }
        );
        if flag_isset(flags, TCP_FLG_RST) {
            return;
        }
        if !flag_isset(flags, TCP_FLG_ACK) {
            let _ = output_segment(
                0,
                seg.seq.wrapping_add(seg.len),
                TCP_FLG_RST | TCP_FLG_ACK,
                0,
                &[],
                local,
                remote,
            );
        } else {
            let _ = output_segment(seg.ack, 0, TCP_FLG_RST, 0, &[], local, remote);
        }
        return;
    }

    let desc = pcb_desc.unwrap();
    let state = pcbs[desc].as_ref().unwrap().state;
    crate::debugf!("desc={}, state={}", desc, state);

    match state {
        TcpState::Listen => {
            // 1st check for an RST
            if flag_isset(flags, TCP_FLG_RST) {
                return;
            }
            // 2nd check for an ACK
            if flag_isset(flags, TCP_FLG_ACK) {
                let _ = output_segment(seg.ack, 0, TCP_FLG_RST, 0, &[], local, remote);
                return;
            }
            // 3rd check for an SYN
            if flag_isset(flags, TCP_FLG_SYN) {
                // ignore: security/compartment check
                let pcb = pcbs[desc].as_mut().unwrap();
                pcb.local = local;
                pcb.remote = remote;
                pcb.rcv.wnd = RECV_BUF_SIZE as u16;
                pcb.rcv.nxt = seg.seq.wrapping_add(1);
                pcb.irs = seg.seq;
                pcb.iss = crate::platform::random32();
                let _ = output(pcb, TCP_FLG_SYN | TCP_FLG_ACK, &[]);
                pcb.snd.nxt = pcb.iss.wrapping_add(1);
                pcb.snd.una = pcb.iss;
                transition(pcb, desc, TcpState::SynReceived);
                // ignore: Note that any other incoming control or data
                // (combined with SYN) will be processed in the SYN-RECEIVED state,
                // but processing of SYN and ACK should not be repeated
            }
            // 4th other text or control: drop segment
            return;
        }
        TcpState::SynSent => {
            // 1st check the ACK bit
            let mut acceptable = false;
            if flag_isset(flags, TCP_FLG_ACK) {
                let pcb = pcbs[desc].as_ref().unwrap();
                if seg.ack <= pcb.iss || seg.ack > pcb.snd.nxt {
                    let _ = output_segment(
                        seg.ack, 0, TCP_FLG_RST, 0, &[], local, remote,
                    );
                    return;
                }
                if pcb.snd.una <= seg.ack && seg.ack <= pcb.snd.nxt {
                    acceptable = true;
                }
            }
            // 2nd check the RST bit
            if flag_isset(flags, TCP_FLG_RST) {
                if acceptable {
                    crate::errorf!("connection reset");
                    let pcb = pcbs[desc].as_mut().unwrap();
                    transition(pcb, desc, TcpState::Closed);
                    let _ = pcb_release(pcbs, desc);
                }
                return;
            }
            // 3rd check security and precedence (ignore)
            // 4th check the SYN bit
            if flag_isset(flags, TCP_FLG_SYN) {
                let pcb = pcbs[desc].as_mut().unwrap();
                pcb.rcv.nxt = seg.seq.wrapping_add(1);
                pcb.irs = seg.seq;
                if acceptable {
                    pcb.snd.una = seg.ack;
                    retrans_queue_cleanup(pcb);
                }
                if pcb.snd.una > pcb.iss {
                    transition(pcb, desc, TcpState::Established);
                    let _ = output(pcb, TCP_FLG_ACK, &[]);
                    // RFC793 does not explicitly initialize the send window here,
                    // but it is required so subsequent send() can compute capacity.
                    pcb.snd.wnd = seg.wnd;
                    pcb.snd.wl1 = seg.seq;
                    pcb.snd.wl2 = seg.ack;
                    let task = pcb.task.clone();
                    task.notify();
                    // ignore: continue processing at the sixth step below where
                    // the URG bit is checked
                    return;
                } else {
                    // simultaneous open
                    transition(pcb, desc, TcpState::SynReceived);
                    let _ = output(pcb, TCP_FLG_SYN | TCP_FLG_ACK, &[]);
                    // ignore: If there are other controls or text in the segment,
                    // queue them for processing after the ESTABLISHED state.
                    return;
                }
            }
            // 5th, if neither SYN nor RST is set, drop the segment
            return;
        }
        _ => {}
    }

    // Otherwise (states other than CLOSED / LISTEN / SYN_SENT)

    // 1st check sequence number
    let acceptable = {
        let pcb = pcbs[desc].as_ref().unwrap();
        let nxt_plus_wnd = pcb.rcv.nxt.wrapping_add(pcb.rcv.wnd as u32);
        if seg.len == 0 {
            if pcb.rcv.wnd == 0 {
                seg.seq == pcb.rcv.nxt
            } else {
                pcb.rcv.nxt <= seg.seq && seg.seq < nxt_plus_wnd
            }
        } else if pcb.rcv.wnd == 0 {
            false
        } else {
            let end_seq = seg.seq.wrapping_add(seg.len).wrapping_sub(1);
            (pcb.rcv.nxt <= seg.seq && seg.seq < nxt_plus_wnd)
                || (pcb.rcv.nxt <= end_seq && end_seq < nxt_plus_wnd)
        }
    };
    if !acceptable {
        if !flag_isset(flags, TCP_FLG_RST) {
            let pcb = pcbs[desc].as_mut().unwrap();
            let _ = output(pcb, TCP_FLG_ACK, &[]);
        }
        return;
    }
    // 2nd check the RST bit
    if flag_isset(flags, TCP_FLG_RST) {
        let state = pcbs[desc].as_ref().unwrap().state;
        match state {
            TcpState::SynReceived
            | TcpState::Closing
            | TcpState::LastAck
            | TcpState::TimeWait => {
                let pcb = pcbs[desc].as_mut().unwrap();
                transition(pcb, desc, TcpState::Closed);
                let _ = pcb_release(pcbs, desc);
            }
            TcpState::Established
            | TcpState::FinWait1
            | TcpState::FinWait2
            | TcpState::CloseWait => {
                crate::errorf!("connection reset");
                let pcb = pcbs[desc].as_mut().unwrap();
                transition(pcb, desc, TcpState::Closed);
                let _ = pcb_release(pcbs, desc);
            }
            _ => {}
        }
        return;
    }
    // 3rd check security and precedence (ignore)
    // 4th check the SYN bit
    if flag_isset(flags, TCP_FLG_SYN) {
        let pcb = pcbs[desc].as_mut().unwrap();
        let _ = output(pcb, TCP_FLG_RST, &[]);
        crate::errorf!("connection reset");
        transition(pcb, desc, TcpState::Closed);
        let _ = pcb_release(pcbs, desc);
        return;
    }

    // 5th check the ACK field
    if !flag_isset(flags, TCP_FLG_ACK) {
        return;
    }
    let pcb = pcbs[desc].as_mut().unwrap();
    if pcb.state == TcpState::SynReceived {
        if pcb.snd.una <= seg.ack && seg.ack <= pcb.snd.nxt {
            transition(pcb, desc, TcpState::Established);
            let task = pcb.task.clone();
            task.notify();
            // fall through to ESTABLISHED
        } else {
            let _ = output_segment(seg.ack, 0, TCP_FLG_RST, 0, &[], local, remote);
            return;
        }
    }
    if matches!(
        pcb.state,
        TcpState::Established
            | TcpState::CloseWait
            | TcpState::FinWait1
            | TcpState::FinWait2
    ) {
        if pcb.snd.una < seg.ack && seg.ack <= pcb.snd.nxt {
            pcb.snd.una = seg.ack;
            retrans_queue_cleanup(pcb);
            // Update send window if this ACK conveys newer information.
            if pcb.snd.wl1 < seg.seq
                || (pcb.snd.wl1 == seg.seq && pcb.snd.wl2 <= seg.ack)
            {
                pcb.snd.wnd = seg.wnd;
                pcb.snd.wl1 = seg.seq;
                pcb.snd.wl2 = seg.ack;
            }
        } else if seg.ack < pcb.snd.una {
            // duplicate ACK: ignore
        } else if pcb.snd.nxt < seg.ack {
            let _ = output(pcb, TCP_FLG_ACK, &[]);
            return;
        }
        // state-specific post-processing
        if pcb.state == TcpState::FinWait1 && seg.ack == pcb.snd.nxt {
            transition(pcb, desc, TcpState::FinWait2);
        }
        // FinWait2 / CloseWait: nothing extra
    } else if pcb.state == TcpState::Closing {
        if seg.ack == pcb.snd.nxt {
            transition(pcb, desc, TcpState::TimeWait);
            set_timewait_timer(pcb);
            let task = pcb.task.clone();
            task.notify();
        }
    } else if pcb.state == TcpState::LastAck {
        if seg.ack == pcb.snd.nxt {
            transition(pcb, desc, TcpState::Closed);
            let _ = pcb_release(pcbs, desc);
        }
        return;
    } else if pcb.state == TcpState::TimeWait {
        if flag_isset(flags, TCP_FLG_FIN) {
            set_timewait_timer(pcb);
        }
    }
    // 6th URG bit (ignore)
    // 7th process segment text (ESTABLISHED)
    let pcb = pcbs[desc].as_mut().unwrap();
    if matches!(
        pcb.state,
        TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2
    ) && !data.is_empty()
    {
        let len = data.len();
        if pcb.rcv.nxt != seg.seq || (pcb.rcv.wnd as usize) < len {
            // Out of order or larger than window: re-ack to request the optimal segment.
            let _ = output(pcb, TCP_FLG_ACK, &[]);
            return;
        }
        crate::debugf!("copy segment text, len={}, wnd={}", len, pcb.rcv.wnd);
        pcb.buf.extend_from_slice(data);
        pcb.rcv.nxt = seg.seq.wrapping_add(len as u32);
        pcb.rcv.wnd -= len as u16;
        let _ = output(pcb, TCP_FLG_ACK, &[]);
        let task = pcb.task.clone();
        task.notify();
    }
    // 8th check the FIN bit
    if flag_isset(flags, TCP_FLG_FIN) {
        let pcb = pcbs[desc].as_mut().unwrap();
        match pcb.state {
            TcpState::Closed | TcpState::Listen => return,
            _ => {}
        }
        pcb.rcv.nxt = seg.seq.wrapping_add(1);
        let _ = output(pcb, TCP_FLG_ACK, &[]);
        match pcb.state {
            TcpState::SynReceived | TcpState::Established => {
                transition(pcb, desc, TcpState::CloseWait);
                let task = pcb.task.clone();
                task.notify();
            }
            TcpState::FinWait1 => {
                // simultaneous close
                if seg.ack == pcb.snd.nxt {
                    transition(pcb, desc, TcpState::TimeWait);
                    set_timewait_timer(pcb);
                } else {
                    transition(pcb, desc, TcpState::Closing);
                }
            }
            TcpState::FinWait2 => {
                transition(pcb, desc, TcpState::TimeWait);
                set_timewait_timer(pcb);
            }
            // CLOSING / CLOSE_WAIT / LAST_ACK / TIME_WAIT: remain in current state
            _ => {}
        }
    }
}

fn input(hdr: &IpHdr<'_>, data: &[u8], iface: &IpIface) {
    if data.len() < TCP_HDR_SIZE {
        crate::errorf!("too short, len={}", data.len());
        return;
    }
    let Some(tcp) = TcpHdr::new(data) else { return };

    let pseudo = build_pseudo_header(hdr.src(), hdr.dst(), data.len() as u16);
    let init = !util::cksum16(&pseudo, 0) as u32;
    if util::cksum16(data, init) != 0 {
        crate::errorf!("checksum error, sum=0x{:04x}", tcp.sum());
        return;
    }

    let src = IpEndp::new(hdr.src(), tcp.src());
    let dst = IpEndp::new(hdr.dst(), tcp.dst());
    if hdr.src() == IpAddr::BROADCAST
        || hdr.src() == iface.broadcast()
        || hdr.dst() == IpAddr::BROADCAST
        || hdr.dst() == iface.broadcast()
    {
        crate::errorf!("only supports unicast, src={}, dst={}", src, dst);
        return;
    }

    crate::debugf!(
        "{} => {}, len={}, dev={}",
        src,
        dst,
        data.len(),
        iface.dev().name,
    );
    print(data);

    let hlen = tcp.hlen();
    let mut seg_len = (data.len() - hlen) as u32;
    if flag_isset(tcp.flg(), TCP_FLG_SYN) {
        seg_len += 1;
    }
    if flag_isset(tcp.flg(), TCP_FLG_FIN) {
        seg_len += 1;
    }
    let seg = SegInfo {
        seq: tcp.seq(),
        ack: tcp.ack(),
        len: seg_len,
        wnd: tcp.wnd(),
        up: tcp.up(),
    };
    let mut pcbs = PCBS.lock();
    segment_arrives(&mut pcbs, &seg, tcp.flg(), &data[hlen..], dst, src);
}

pub fn open(local: IpEndp, remote: IpEndp, active: bool) -> Result<TcpDesc, ()> {
    let desc = {
        let mut pcbs = PCBS.lock();
        let desc = pcb_alloc(&mut pcbs).ok_or_else(|| {
            crate::errorf!("pcb_alloc() failure");
        })?;
        crate::debugf!(
            "mode={}, local={}, remote={}",
            if active { "active" } else { "passive" },
            local,
            remote
        );
        if active {
            let mut local = local;
            // Auto-select local address if wildcard.
            if local.addr == IpAddr::ANY {
                let Some(route) = ip::route_lookup(remote.addr) else {
                    crate::errorf!(
                        "iface not found that can reach remote address, addr={}",
                        remote.addr
                    );
                    let _ = pcb_release(&mut pcbs, desc);
                    return Err(());
                };
                local.addr = route.iface.unicast();
                crate::debugf!("select local address, addr={}", local.addr);
            }
            // Dynamically assign local port if 0.
            if local.port == 0 {
                let mut assigned = None;
                for port in DYNAMIC_PORT_MIN..=DYNAMIC_PORT_MAX {
                    let candidate = IpEndp::new(local.addr, port);
                    if pcb_select(&pcbs, candidate, remote).is_none() {
                        assigned = Some(port);
                        break;
                    }
                }
                match assigned {
                    Some(port) => {
                        local.port = port;
                        crate::debugf!("dynamic assign local port, port={}", port);
                    }
                    None => {
                        crate::errorf!(
                            "failed to dynamic assign local port, addr={}",
                            local.addr
                        );
                        let _ = pcb_release(&mut pcbs, desc);
                        return Err(());
                    }
                }
            }
            if pcb_select(&pcbs, local, remote).is_some() {
                crate::errorf!("address already in use");
                let _ = pcb_release(&mut pcbs, desc);
                return Err(());
            }
            let pcb = pcb_get_mut(&mut pcbs, desc).unwrap();
            pcb.local = local;
            pcb.remote = remote;
            pcb.rcv.wnd = RECV_BUF_SIZE as u16;
            pcb.iss = crate::platform::random32();
            if output(pcb, TCP_FLG_SYN, &[]).is_err() {
                crate::errorf!("tcp::output() failure");
                transition(pcb, desc, TcpState::Closed);
                let _ = pcb_release(&mut pcbs, desc);
                return Err(());
            }
            pcb.snd.una = pcb.iss;
            pcb.snd.nxt = pcb.iss.wrapping_add(1);
            transition(pcb, desc, TcpState::SynSent);
        } else {
            if pcb_select(&pcbs, local, remote).is_some() {
                crate::errorf!("address already in use");
                let _ = pcb_release(&mut pcbs, desc);
                return Err(());
            }
            let pcb = pcb_get_mut(&mut pcbs, desc).unwrap();
            pcb.local = local;
            pcb.remote = remote;
            transition(pcb, desc, TcpState::Listen);
            crate::debugf!("waiting for connection...");
        }
        desc
    };

    // Wait for state to become ESTABLISHED (or fail).
    loop {
        let (task, snapshot) = {
            let mut pcbs = PCBS.lock();
            let pcb = pcb_get_mut(&mut pcbs, desc).ok_or(())?;
            match pcb.state {
                TcpState::Established => break,
                TcpState::Listen | TcpState::SynReceived | TcpState::SynSent => {
                    (pcb.task.clone(), pcb.task.snapshot())
                }
                other => {
                    crate::errorf!("open error: state={}", other);
                    transition(pcb, desc, TcpState::Closed);
                    let _ = pcb_release(&mut pcbs, desc);
                    return Err(());
                }
            }
        };
        match task.wait_after(snapshot) {
            WaitResult::Notified => continue,
            WaitResult::Interrupted => {
                crate::debugf!("interrupted");
                let mut pcbs = PCBS.lock();
                if let Some(pcb) = pcb_get_mut(&mut pcbs, desc) {
                    transition(pcb, desc, TcpState::Closed);
                }
                let _ = pcb_release(&mut pcbs, desc);
                return Err(());
            }
        }
    }

    // ESTABLISHED. Compute MSS from the outgoing interface MTU.
    let mut pcbs = PCBS.lock();
    let pcb = pcb_get_mut(&mut pcbs, desc).ok_or(())?;
    let route = ip::route_lookup(pcb.remote.addr).ok_or_else(|| {
        crate::errorf!("iface not found");
    })?;
    let mtu = route.iface.dev().mtu as usize;
    pcb.mss = (mtu - IP_HDR_SIZE_MIN - TCP_HDR_SIZE) as u16;
    crate::debugf!("success, local={}, remote={}", pcb.local, pcb.remote);
    Ok(desc)
}

pub fn close(desc: TcpDesc) -> Result<(), ()> {
    let mut pcbs = PCBS.lock();
    let pcb = pcb_get_mut(&mut pcbs, desc).ok_or_else(|| {
        crate::errorf!("pcb not found, desc={}", desc);
    })?;
    crate::debugf!("desc={}", desc);
    match pcb.state {
        TcpState::Closed => {
            crate::errorf!("connection does not exist");
            return Err(());
        }
        TcpState::Listen | TcpState::SynSent => {
            transition(pcb, desc, TcpState::Closed);
        }
        TcpState::SynReceived | TcpState::Established => {
            crate::debugf!("close connection");
            let _ = output(pcb, TCP_FLG_ACK | TCP_FLG_FIN, &[]);
            pcb.snd.nxt = pcb.snd.nxt.wrapping_add(1);
            transition(pcb, desc, TcpState::FinWait1);
        }
        TcpState::CloseWait => {
            crate::debugf!("close connection");
            let _ = output(pcb, TCP_FLG_ACK | TCP_FLG_FIN, &[]);
            pcb.snd.nxt = pcb.snd.nxt.wrapping_add(1);
            transition(pcb, desc, TcpState::LastAck);
        }
        TcpState::FinWait1
        | TcpState::FinWait2
        | TcpState::Closing
        | TcpState::LastAck
        | TcpState::TimeWait => {
            crate::errorf!("connection closing");
            return Err(());
        }
    }
    if pcbs[desc].as_ref().map(|p| p.state) == Some(TcpState::Closed) {
        pcb_release(&mut pcbs, desc)?;
    } else {
        let task = pcb_get_mut(&mut pcbs, desc).unwrap().task.clone();
        task.notify();
    }
    Ok(())
}

pub fn send(desc: TcpDesc, data: &[u8]) -> Result<usize, ()> {
    let mut sent: usize = 0;
    loop {
        let wait = {
            let mut pcbs = PCBS.lock();
            let pcb = pcb_get_mut(&mut pcbs, desc).ok_or_else(|| {
                crate::errorf!("pcb not found, desc={}", desc);
            })?;
            match pcb.state {
                TcpState::Established | TcpState::CloseWait => {}
                TcpState::FinWait1
                | TcpState::FinWait2
                | TcpState::Closing
                | TcpState::LastAck
                | TcpState::TimeWait => {
                    crate::errorf!("connection closing");
                    return Err(());
                }
                other => {
                    crate::errorf!("invalid state '{}'", other);
                    return Err(());
                }
            }
            if sent >= data.len() {
                return Ok(sent);
            }
            let in_flight = pcb.snd.nxt.wrapping_sub(pcb.snd.una);
            let cap = (pcb.snd.wnd as u32).saturating_sub(in_flight);
            if cap == 0 {
                Some((pcb.task.clone(), pcb.task.snapshot()))
            } else {
                let remain = data.len() - sent;
                let slen = (pcb.mss as usize).min(remain).min(cap as usize);
                let _ = output(pcb, TCP_FLG_ACK | TCP_FLG_PSH, &data[sent..sent + slen]);
                pcb.snd.nxt = pcb.snd.nxt.wrapping_add(slen as u32);
                sent += slen;
                None
            }
        };
        if let Some((task, snapshot)) = wait {
            match task.wait_after(snapshot) {
                WaitResult::Notified => continue,
                WaitResult::Interrupted => {
                    crate::debugf!("interrupted");
                    if sent == 0 {
                        return Err(());
                    }
                    return Ok(sent);
                }
            }
        }
    }
}

pub fn receive(desc: TcpDesc, buf: &mut [u8]) -> Result<usize, ()> {
    loop {
        let wait = {
            let mut pcbs = PCBS.lock();
            let pcb = pcb_get_mut(&mut pcbs, desc).ok_or_else(|| {
                crate::errorf!("pcb not found, desc={}", desc);
            })?;
            match pcb.state {
                TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2 => {
                    if pcb.buf.is_empty() {
                        Some((pcb.task.clone(), pcb.task.snapshot()))
                    } else {
                        let n = buf.len().min(pcb.buf.len());
                        buf[..n].copy_from_slice(&pcb.buf[..n]);
                        pcb.buf.drain(..n);
                        pcb.rcv.wnd += n as u16;
                        return Ok(n);
                    }
                }
                TcpState::CloseWait => {
                    if pcb.buf.is_empty() {
                        crate::debugf!("connection closing");
                        return Ok(0);
                    }
                    let n = buf.len().min(pcb.buf.len());
                    buf[..n].copy_from_slice(&pcb.buf[..n]);
                    pcb.buf.drain(..n);
                    pcb.rcv.wnd += n as u16;
                    return Ok(n);
                }
                TcpState::Closing | TcpState::LastAck | TcpState::TimeWait => {
                    crate::debugf!("connection closing");
                    return Ok(0);
                }
                other => {
                    crate::errorf!("unknown state '{}'", other);
                    return Err(());
                }
            }
        };
        if let Some((task, snapshot)) = wait {
            match task.wait_after(snapshot) {
                WaitResult::Notified => continue,
                WaitResult::Interrupted => {
                    crate::debugf!("interrupted");
                    return Err(());
                }
            }
        }
    }
}

pub fn init() -> Result<(), ()> {
    ip::register_protocol(IP_PROTOCOL_TCP, input)?;
    crate::platform::timer::register(TCP_TIMER_INTERVAL, Box::new(on_timer))?;
    Ok(())
}
