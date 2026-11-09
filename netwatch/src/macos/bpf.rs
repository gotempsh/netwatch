//! Packet capture with /dev/bpf, and pcap files for replaying captures.
//!
//! The extended header (BIOCSEXTHDR, private in the SDK but stable since
//! 10.8; see xnu bsd/net/bpf_private.h) says whether each packet came in or
//! went out, and for outgoing TCP/UDP the pid and name of the sending process.

use std::{
    ffi::CString,
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    path::Path,
};

// ioctl numbers, from <net/bpf.h> (checked against the macOS SDK) and xnu's bpf_private.h.
const BIOCSBLEN: libc::c_ulong = 0xc004_4266;
const BIOCGBLEN: libc::c_ulong = 0x4004_4266;
const BIOCSETF: libc::c_ulong = 0x8010_4267;
const BIOCGDLT: libc::c_ulong = 0x4004_426a;
const BIOCSETIF: libc::c_ulong = 0x8020_426c;
const BIOCSRTIMEOUT: libc::c_ulong = 0x8010_426d;
const BIOCGSTATS: libc::c_ulong = 0x4008_426f;
const BIOCSSEESENT: libc::c_ulong = 0x8004_4277;
const BIOCSEXTHDR: libc::c_ulong = 0x8004_427c;

pub const DLT_NULL: u32 = 0;
pub const DLT_EN10MB: u32 = 1;
pub const DLT_RAW: u32 = 12;
pub const DLT_LOOP: u32 = 108;
/// pcap files use LINKTYPE_RAW (101) where BPF uses DLT_RAW (12).
const LINKTYPE_RAW: u32 = 101;

/// Records are padded to 4 bytes (BPF_ALIGNMENT is sizeof(int32_t)).
fn word_align(x: usize) -> usize {
    (x + 3) & !3
}

/// Per-packet header fields we use. Offsets are those of `struct bpf_hdr_ext`
/// (64 bytes); the plain `struct bpf_hdr` shares the first 18 bytes.
const HDR_CAPLEN: usize = 8;
const HDR_DATALEN: usize = 12;
const HDR_HDRLEN: usize = 16;
const EXT_FLAGS: usize = 19;
const EXT_PID: usize = 20;
const EXT_COMM: usize = 24;
const EXT_PKTFLAGS: usize = 41;
const EXT_FLAGS_DIR_OUT: u8 = 0x01;
const PKTFLAGS_TCP_REXMT: u8 = 0x01;

/// One captured frame.
pub struct Frame<'a> {
    pub ts_unix_ns: i128,
    pub wire_len: u32,
    /// None when the capture doesn't say (no extended header, pcap files).
    pub egress: Option<bool>,
    pub pid: u32,
    pub comm: [u8; 16],
    pub retransmit: bool,
    pub data: &'a [u8],
}

pub struct Device {
    fd: OwnedFd,
    buf: Vec<u8>,
    filled: usize,
    pub dlt: u32,
    /// Extended headers: direction and process per packet.
    pub ext: bool,
}

fn ioctl<T>(fd: &OwnedFd, req: libc::c_ulong, arg: &mut T) -> io::Result<()> {
    // SAFETY: every request used here takes a pointer to a T of the size encoded in `req`.
    if unsafe { libc::ioctl(fd.as_raw_fd(), req, arg as *mut T) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[repr(C)]
struct BpfInsn {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct BpfProgram {
    len: u32,
    insns: *const BpfInsn,
}

impl Device {
    /// Opens a free /dev/bpfN on `iface`, copying at most `snaplen` bytes per packet.
    pub fn open(iface: &str, snaplen: u32) -> io::Result<Self> {
        let fd = Self::open_free()?;
        // The kernel caps this at debug.bpf_maxbufsize; must precede BIOCSETIF.
        let mut blen: u32 = 4 << 20;
        let _ = ioctl(&fd, BIOCSBLEN, &mut blen);
        let mut one: u32 = 1;
        let ext = ioctl(&fd, BIOCSEXTHDR, &mut one).is_ok();

        let mut ifr = [0u8; 32];
        let name = iface.as_bytes();
        if name.len() >= 16 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface name too long",
            ));
        }
        ifr[..name.len()].copy_from_slice(name);
        ioctl(&fd, BIOCSETIF, &mut ifr)?;
        let mut one: u32 = 1;
        ioctl(&fd, BIOCSSEESENT, &mut one)?;
        // Reads return at least every 250 ms, so stop requests are noticed.
        let mut tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 250_000,
        };
        ioctl(&fd, BIOCSRTIMEOUT, &mut tv)?;
        // "ret #snaplen": accept every packet, truncated.
        let insn = [BpfInsn {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: snaplen,
        }];
        let mut prog = BpfProgram {
            len: 1,
            insns: insn.as_ptr(),
        };
        ioctl(&fd, BIOCSETF, &mut prog)?;
        let mut dlt: u32 = 0;
        ioctl(&fd, BIOCGDLT, &mut dlt)?;
        let mut blen: u32 = 0;
        ioctl(&fd, BIOCGBLEN, &mut blen)?;
        Ok(Self {
            fd,
            buf: vec![0; blen.max(4096) as usize],
            filled: 0,
            dlt,
            ext,
        })
    }

    fn open_free() -> io::Result<OwnedFd> {
        let mut last = io::Error::from(io::ErrorKind::NotFound);
        for i in 0..256 {
            let path = CString::new(format!("/dev/bpf{i}")).expect("no NUL");
            // SAFETY: plain open(2) of a NUL-terminated path.
            let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
            if fd >= 0 {
                // SAFETY: fd was just opened and is owned by nobody else.
                return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
            }
            last = io::Error::last_os_error();
            match last.raw_os_error() {
                Some(libc::EBUSY) => continue,
                // Devices are created on demand; a missing one means all are taken.
                Some(libc::ENOENT) => break,
                _ => return Err(last),
            }
        }
        Err(last)
    }

    /// Waits up to the read timeout for packets; false on timeout.
    pub fn fill(&mut self) -> io::Result<bool> {
        // SAFETY: reads into our own buffer of the size the kernel asked for.
        let n = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                self.buf.as_mut_ptr().cast(),
                self.buf.len(),
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            return match e.raw_os_error() {
                Some(libc::EINTR | libc::EAGAIN) => {
                    self.filled = 0;
                    Ok(false)
                }
                _ => Err(e),
            };
        }
        self.filled = n as usize;
        Ok(n > 0)
    }

    pub fn frames(&self) -> Frames<'_> {
        Frames {
            buf: &self.buf[..self.filled],
            pos: 0,
            ext: self.ext,
        }
    }

    /// (received, dropped because the buffer was full) since open.
    pub fn stats(&self) -> Option<(u32, u32)> {
        let mut st = [0u32; 2];
        ioctl(&self.fd, BIOCGSTATS, &mut st).ok()?;
        Some((st[0], st[1]))
    }
}

pub struct Frames<'a> {
    buf: &'a [u8],
    pos: usize,
    ext: bool,
}

fn u32_at(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(b.get(i..i + 4)?.try_into().ok()?))
}

impl<'a> Iterator for Frames<'a> {
    type Item = Frame<'a>;

    fn next(&mut self) -> Option<Frame<'a>> {
        let b = self.buf.get(self.pos..)?;
        let caplen = u32_at(b, HDR_CAPLEN)? as usize;
        let datalen = u32_at(b, HDR_DATALEN)?;
        let hdrlen =
            u16::from_ne_bytes(b.get(HDR_HDRLEN..HDR_HDRLEN + 2)?.try_into().ok()?) as usize;
        let data = b.get(hdrlen..hdrlen + caplen)?;
        let sec = i32::from_ne_bytes(b[0..4].try_into().ok()?) as i128;
        let usec = i32::from_ne_bytes(b[4..8].try_into().ok()?) as i128;
        let (egress, pid, comm, retransmit) = if self.ext && hdrlen > EXT_PKTFLAGS {
            let mut comm = [0u8; 16];
            comm.copy_from_slice(&b[EXT_COMM..EXT_COMM + 16]);
            (
                Some(b[EXT_FLAGS] & EXT_FLAGS_DIR_OUT != 0),
                i32::from_ne_bytes(b[EXT_PID..EXT_PID + 4].try_into().ok()?).max(0) as u32,
                comm,
                b[EXT_PKTFLAGS] & PKTFLAGS_TCP_REXMT != 0,
            )
        } else {
            (None, 0, [0; 16], false)
        };
        self.pos += word_align(hdrlen + caplen);
        Some(Frame {
            ts_unix_ns: sec * 1_000_000_000 + usec * 1000,
            wire_len: datalen,
            egress,
            pid,
            comm,
            retransmit,
            data,
        })
    }
}

/// What follows the link-layer header.
pub enum L3<'a> {
    Ip(&'a [u8]),
    /// ARP, LLDP and other non-IP frames (counted, like XDP's non_ip).
    Other,
}

fn ip(b: &[u8]) -> L3<'_> {
    match b.first().map(|v| v >> 4) {
        Some(4 | 6) => L3::Ip(b),
        _ => L3::Other,
    }
}

pub fn l3(dlt: u32, data: &[u8]) -> L3<'_> {
    match dlt {
        DLT_EN10MB => {
            let Some(mut et) = data.get(12..14).map(|b| u16::from_be_bytes([b[0], b[1]])) else {
                return L3::Other;
            };
            let mut off = 14;
            if et == 0x8100 || et == 0x88a8 {
                match data.get(16..18) {
                    Some(b) => et = u16::from_be_bytes([b[0], b[1]]),
                    None => return L3::Other,
                }
                off = 18;
            }
            match et {
                0x0800 | 0x86dd => ip(&data[off..]),
                _ => L3::Other,
            }
        }
        // A 4-byte address family (host order for NULL, network order for LOOP).
        DLT_NULL | DLT_LOOP => data.get(4..).map_or(L3::Other, ip),
        DLT_RAW | LINKTYPE_RAW => ip(data),
        _ => L3::Other,
    }
}

/// A classic pcap file, read whole: (dlt, frames). For tests and NETWATCH_PCAP.
pub struct Pcap {
    pub dlt: u32,
    pub frames: Vec<(i128, u32, Vec<u8>)>,
}

impl Pcap {
    pub fn read(path: &Path) -> io::Result<Self> {
        Self::parse(&std::fs::read(path)?)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "not a pcap file"))
    }

    pub fn parse(b: &[u8]) -> Option<Self> {
        let magic = u32::from_le_bytes(b.get(0..4)?.try_into().ok()?);
        let (le, nanos) = match magic {
            0xa1b2c3d4 => (true, false),
            0xa1b23c4d => (true, true),
            0xd4c3b2a1 => (false, false),
            0x4d3cb2a1 => (false, true),
            _ => return None,
        };
        let rd = |i: usize| -> Option<u32> {
            let a: [u8; 4] = b.get(i..i + 4)?.try_into().ok()?;
            Some(if le {
                u32::from_le_bytes(a)
            } else {
                u32::from_be_bytes(a)
            })
        };
        let dlt = rd(20)?;
        let mut frames = Vec::new();
        let mut pos = 24;
        while pos + 16 <= b.len() {
            let (sec, sub, incl, orig) =
                (rd(pos)?, rd(pos + 4)?, rd(pos + 8)? as usize, rd(pos + 12)?);
            let data = b.get(pos + 16..pos + 16 + incl)?.to_vec();
            let ns = sec as i128 * 1_000_000_000 + sub as i128 * if nanos { 1 } else { 1000 };
            frames.push((ns, orig, data));
            pos += 16 + incl;
        }
        Some(Self { dlt, frames })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extended_records() {
        // Two records as the kernel lays them out: 64-byte header, data, 4-byte padding.
        let mut buf = Vec::new();
        for (out, pid, data) in [
            (true, 812i32, &b"\x45abc"[..]),
            (false, 0, &b"\x60defgh"[..]),
        ] {
            let mut h = [0u8; 64];
            h[0..4].copy_from_slice(&1_700_000_000i32.to_ne_bytes());
            h[4..8].copy_from_slice(&250_000i32.to_ne_bytes());
            h[8..12].copy_from_slice(&(data.len() as u32).to_ne_bytes());
            h[12..16].copy_from_slice(&1514u32.to_ne_bytes());
            h[16..18].copy_from_slice(&64u16.to_ne_bytes());
            h[19] = out as u8;
            h[20..24].copy_from_slice(&pid.to_ne_bytes());
            h[24..29].copy_from_slice(b"Slack");
            h[41] = out as u8;
            buf.extend_from_slice(&h);
            buf.extend_from_slice(data);
            buf.resize(word_align(buf.len()), 0);
        }
        let frames: Vec<Frame> = Frames {
            buf: &buf,
            pos: 0,
            ext: true,
        }
        .collect();
        assert_eq!(frames.len(), 2);
        assert_eq!(
            (
                frames[0].egress,
                frames[0].pid,
                &frames[0].comm[..5],
                frames[0].retransmit,
                frames[0].wire_len
            ),
            (Some(true), 812, &b"Slack"[..], true, 1514)
        );
        assert_eq!(frames[0].ts_unix_ns, 1_700_000_000_250_000_000);
        assert_eq!(
            (frames[1].egress, frames[1].data),
            (Some(false), &b"\x60defgh"[..])
        );
    }

    #[test]
    fn link_layers() {
        let mut eth = vec![0u8; 14];
        eth[12] = 0x08;
        eth.push(0x45);
        assert!(matches!(l3(DLT_EN10MB, &eth), L3::Ip(b) if b == [0x45]));
        let mut vlan = vec![0u8; 18];
        vlan[12] = 0x81;
        vlan[16] = 0x86;
        vlan[17] = 0xdd;
        vlan.push(0x60);
        assert!(matches!(l3(DLT_EN10MB, &vlan), L3::Ip(b) if b == [0x60]));
        let mut arp = vec![0u8; 14];
        arp[12] = 0x08;
        arp[13] = 0x06;
        assert!(matches!(l3(DLT_EN10MB, &arp), L3::Other));
        assert!(matches!(l3(DLT_NULL, &[2, 0, 0, 0, 0x45]), L3::Ip(_)));
        assert!(matches!(l3(DLT_RAW, &[0x45]), L3::Ip(_)));
    }

    #[test]
    fn pcap_files() {
        let mut f = Vec::new();
        f.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
        f.extend_from_slice(&[2, 0, 4, 0]);
        f.extend_from_slice(&[0; 8]);
        f.extend_from_slice(&65535u32.to_le_bytes());
        f.extend_from_slice(&1u32.to_le_bytes());
        for v in [10u32, 5, 3, 60] {
            f.extend_from_slice(&v.to_le_bytes());
        }
        f.extend_from_slice(b"abc");
        let p = Pcap::parse(&f).unwrap();
        assert_eq!(p.dlt, 1);
        assert_eq!(p.frames, vec![(10_000_005_000, 60, b"abc".to_vec())]);
    }
}
