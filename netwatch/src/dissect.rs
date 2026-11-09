//! Metadata from the first bytes of a payload: DNS messages, TLS ClientHello
//! (SNI, ALPN), HTTP request/response lines and SSH banners. Only these parsed
//! fields are kept; raw payload bytes never leave this module.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum DnsData {
    Addr(IpAddr),
    Name(String),
    Other,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DnsAnswer {
    pub name: String,
    pub rtype: u16,
    pub ttl: u32,
    pub data: DnsData,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DnsMsg {
    pub id: u16,
    pub response: bool,
    pub rcode: u8,
    /// Header flags word: QR, opcode, AA, TC, RD, RA, Z, AD, CD, rcode.
    pub flags: u16,
    /// Section counts from the header: questions, answers, authority, additional.
    pub counts: [u16; 4],
    pub questions: Vec<(String, u16)>,
    /// Class of the first question.
    pub qclass: Option<u16>,
    pub answers: Vec<DnsAnswer>,
}

impl DnsMsg {
    pub fn opcode(&self) -> u8 {
        ((self.flags >> 11) & 0xf) as u8
    }

    fn one_question(&self) -> bool {
        self.counts[0] == 1
            && self.questions.len() == 1
            && self.questions[0].1 != 0
            && matches!(self.qclass, Some(1 | 3 | 4 | 255)) // IN, CH, HS, ANY
    }

    /// A standard query as a resolver sends it: QR, AA, TC and RA clear, opcode
    /// QUERY, reserved bit clear, one question, no records in the other
    /// sections (but room for an EDNS OPT). Random bytes and other protocols
    /// on port 53 rarely satisfy all of that.
    pub fn is_plain_query(&self) -> bool {
        const QR_AA_TC_RA_Z: u16 = 0x8000 | 0x0400 | 0x0200 | 0x0080 | 0x0040;
        let [_, an, ns, ar] = self.counts;
        self.flags & QR_AA_TC_RA_Z == 0
            && self.opcode() == 0
            && self.rcode == 0
            && an == 0
            && ns == 0
            && ar <= 4
            && self.one_question()
    }

    /// A standard-query response: QR set, opcode QUERY, echoing one question.
    pub fn is_plain_response(&self) -> bool {
        self.response && self.opcode() == 0 && self.flags & 0x0040 == 0 && self.one_question()
    }
}

fn be16(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

fn be32(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *b.get(i)?,
        *b.get(i + 1)?,
        *b.get(i + 2)?,
        *b.get(i + 3)?,
    ]))
}

/// Reads a possibly-compressed name at `pos`; returns (name, position after it).
fn dns_name(b: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut end = None;
    for _ in 0..64 {
        let len = *b.get(pos)? as usize;
        match len {
            0 => {
                let after = end.unwrap_or(pos + 1);
                let name = if labels.is_empty() {
                    ".".to_string()
                } else {
                    labels.join(".")
                };
                return Some((name.to_ascii_lowercase(), after));
            }
            l if l & 0xc0 == 0xc0 => {
                let ptr = ((l & 0x3f) << 8) | *b.get(pos + 1)? as usize;
                end.get_or_insert(pos + 2);
                if ptr >= pos {
                    return None; // pointers only go backwards; avoids loops
                }
                pos = ptr;
            }
            l if l <= 63 => {
                let label = b.get(pos + 1..pos + 1 + l)?;
                labels.push(
                    label
                        .iter()
                        .map(|&c| if c.is_ascii_graphic() { c as char } else { '?' })
                        .collect(),
                );
                pos += 1 + l;
            }
            _ => return None,
        }
    }
    None
}

pub fn dns(b: &[u8]) -> Option<DnsMsg> {
    if b.len() < 12 {
        return None;
    }
    let id = be16(b, 0)?;
    let flags = be16(b, 2)?;
    let counts = [be16(b, 4)?, be16(b, 6)?, be16(b, 8)?, be16(b, 10)?];
    let (qd, an) = (counts[0] as usize, counts[1] as usize);
    if qd > 16 || an > 64 {
        return None;
    }
    let mut pos = 12;
    let mut questions = Vec::with_capacity(qd);
    let mut qclass = None;
    for _ in 0..qd {
        let (name, p) = dns_name(b, pos)?;
        questions.push((name, be16(b, p)?));
        if qclass.is_none() {
            qclass = be16(b, p + 2);
        }
        pos = p + 4;
    }
    let mut answers = Vec::new();
    // Answers may be cut off by the capture length; keep what parsed.
    for _ in 0..an {
        let Some((name, p)) = dns_name(b, pos) else {
            break;
        };
        let (Some(rtype), Some(ttl), Some(rdlen)) = (be16(b, p), be32(b, p + 4), be16(b, p + 8))
        else {
            break;
        };
        let rd = p + 10;
        let rdlen = rdlen as usize;
        let Some(rdata) = b.get(rd..rd + rdlen) else {
            break;
        };
        let data = match (rtype, rdlen) {
            (1, 4) => DnsData::Addr(IpAddr::V4(Ipv4Addr::new(
                rdata[0], rdata[1], rdata[2], rdata[3],
            ))),
            (28, 16) => DnsData::Addr(IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(rdata).ok()?,
            ))),
            (5, _) => dns_name(b, rd).map_or(DnsData::Other, |(n, _)| DnsData::Name(n)),
            _ => DnsData::Other,
        };
        answers.push(DnsAnswer {
            name,
            rtype,
            ttl,
            data,
        });
        pos = rd + rdlen;
    }
    Some(DnsMsg {
        id,
        response: flags & 0x8000 != 0,
        rcode: (flags & 0x000f) as u8,
        flags,
        counts,
        questions,
        qclass,
        answers,
    })
}

pub fn qtype_name(t: u16) -> String {
    match t {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        64 => "SVCB".into(),
        65 => "HTTPS".into(),
        255 => "ANY".into(),
        t => format!("TYPE{t}"),
    }
}

pub fn rcode_name(r: u8) -> &'static str {
    match r {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "OTHER",
    }
}

/// What the first payload of one TCP direction says about the connection.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct AppMeta {
    /// tls, http, ssh, or None when unrecognised.
    pub proto: Option<&'static str>,
    pub sni: Option<String>,
    pub alpn: Option<String>,
    pub http_method: Option<String>,
    pub http_host: Option<String>,
    pub http_path: Option<String>,
    pub user_agent: Option<String>,
    pub http_status: Option<u16>,
    pub server: Option<String>,
    /// SSH version string from the client side.
    pub ssh_client: Option<String>,
    pub ssh_server: Option<String>,
    /// Last name asked in a DNS conversation.
    pub dns_qname: Option<String>,
    /// A known exploit in what the client sent (see exploits.rs).
    pub exploit: Option<&'static str>,
    pub cve: Option<&'static str>,
    #[serde(skip)]
    pub exploit_sig: Option<&'static crate::exploits::Signature>,
}

impl AppMeta {
    /// Fills in fields this sample provides; `from_initiator` says which side sent it.
    pub fn absorb(&mut self, data: &[u8], from_initiator: bool) {
        if let Some((sni, alpn)) = tls_client_hello(data) {
            self.proto = Some("tls");
            self.sni = self.sni.take().or(sni);
            self.alpn = self.alpn.take().or(alpn);
        } else if data.len() >= 3 && data[0] == 0x16 && data[1] == 0x03 {
            self.proto = Some("tls");
        } else if let Some(v) = data.strip_prefix(b"SSH-") {
            self.proto = Some("ssh");
            let line = text_line(v, 120);
            let banner = Some(format!("SSH-{line}"));
            if from_initiator {
                self.ssh_client = banner
            } else {
                self.ssh_server = banner
            }
        } else if let Some(req) = http_request(data) {
            self.proto = Some("http");
            self.http_method = Some(req.0);
            self.http_path = Some(req.1);
            self.http_host = req.2;
            self.user_agent = req.3;
            if from_initiator {
                self.match_exploit(data);
            }
        } else if let Some((status, server)) = http_response(data) {
            self.proto.get_or_insert("http");
            self.http_status = Some(status);
            self.server = server;
        } else if from_initiator {
            // Unrecognised plaintext (Redis, raw shell commands...).
            self.match_exploit(data);
        }
    }

    fn match_exploit(&mut self, data: &[u8]) {
        if self.exploit_sig.is_none() {
            if let Some(s) = crate::exploits::match_request(data) {
                self.exploit = Some(s.name);
                self.cve = s.cve;
                self.exploit_sig = Some(s);
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.proto.is_none() && self.exploit.is_none()
    }
}

fn text_line(b: &[u8], max: usize) -> String {
    b.iter()
        .take_while(|&&c| c != b'\r' && c != b'\n')
        .take(max)
        .map(|&c| {
            if c.is_ascii_graphic() || c == b' ' {
                c as char
            } else {
                '?'
            }
        })
        .collect()
}

/// (SNI, ALPN list) from a TLS ClientHello record.
pub fn tls_client_hello(b: &[u8]) -> Option<(Option<String>, Option<String>)> {
    // Record header: type 22 (handshake), version, length; then handshake type 1.
    if b.len() < 43 || b[0] != 0x16 || b[1] != 0x03 || b[5] != 0x01 {
        return None;
    }
    let mut p = 5 + 4 + 2 + 32; // record hdr, handshake hdr, client version, random
    p += 1 + *b.get(p)? as usize; // session id
    p += 2 + be16(b, p)? as usize; // cipher suites
    p += 1 + *b.get(p)? as usize; // compression methods
    let ext_end = (p + 2 + be16(b, p)? as usize).min(b.len());
    p += 2;
    let (mut sni, mut alpn) = (None, None);
    while p + 4 <= ext_end {
        let (ty, len) = (be16(b, p)?, be16(b, p + 2)? as usize);
        let body = p + 4;
        match ty {
            0 => {
                // server_name_list: u16 len, then (u8 type, u16 len, name)
                if let (Some(&0), Some(n)) = (b.get(body + 2), be16(b, body + 3)) {
                    if let Some(name) = b.get(body + 5..body + 5 + n as usize) {
                        sni = Some(String::from_utf8_lossy(name).to_ascii_lowercase());
                    }
                }
            }
            16 => {
                let mut q = body + 2;
                let mut protos = Vec::new();
                while q < body + len {
                    let Some(&l) = b.get(q) else { break };
                    let Some(name) = b.get(q + 1..q + 1 + l as usize) else {
                        break;
                    };
                    protos.push(String::from_utf8_lossy(name).into_owned());
                    q += 1 + l as usize;
                }
                if !protos.is_empty() {
                    alpn = Some(protos.join(","));
                }
            }
            _ => {}
        }
        p = body + len;
    }
    Some((sni, alpn))
}

const METHODS: [&str; 9] = [
    "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "CONNECT", "PRI",
];

/// (method, path, Host, User-Agent)
fn http_request(b: &[u8]) -> Option<(String, String, Option<String>, Option<String>)> {
    let first = text_line(b, 300);
    let mut parts = first.split(' ');
    let method = parts.next()?;
    if !METHODS.contains(&method) {
        return None;
    }
    let path = parts.next()?.chars().take(200).collect();
    if !parts.next()?.starts_with("HTTP/") {
        return None;
    }
    let (mut host, mut ua) = (None, None);
    for line in String::from_utf8_lossy(b).split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            match k.trim().to_ascii_lowercase().as_str() {
                "host" => host = Some(v.trim().chars().take(200).collect()),
                "user-agent" => ua = Some(v.trim().chars().take(200).collect()),
                _ => {}
            }
        }
    }
    Some((method.to_string(), path, host, ua))
}

fn http_response(b: &[u8]) -> Option<(u16, Option<String>)> {
    let first = text_line(b, 100);
    let rest = first.strip_prefix("HTTP/")?;
    let status = rest.split(' ').nth(1)?.parse().ok()?;
    let server = String::from_utf8_lossy(b)
        .split("\r\n")
        .skip(1)
        .take_while(|l| !l.is_empty())
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim()
                .eq_ignore_ascii_case("server")
                .then(|| v.trim().chars().take(120).collect())
        });
    Some((status, server))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_response_with_compression() {
        // Query example.com A, answer CNAME -> www.example.com (pointer), then A.
        let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0];
        m.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        m.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 6]);
        m.extend_from_slice(b"\x03www\xc0\x0c");
        let www = m.len() - 6;
        m.extend_from_slice(&[
            0xc0, www as u8, 0, 1, 0, 1, 0, 0, 1, 0, 0, 4, 93, 184, 216, 34,
        ]);
        let d = dns(&m).unwrap();
        assert!(d.response);
        assert_eq!(d.questions, vec![("example.com".to_string(), 1)]);
        assert_eq!(d.answers[0].data, DnsData::Name("www.example.com".into()));
        assert_eq!(d.answers[1].name, "www.example.com");
        assert_eq!(
            d.answers[1].data,
            DnsData::Addr("93.184.216.34".parse().unwrap())
        );
        // A forward pointer is rejected instead of looping.
        assert!(dns_name(&[0xc0, 0x05, 0, 0, 0, 0], 0).is_none());
        assert!(d.is_plain_response() && !d.is_plain_query());
    }

    /// Header + one question for `name` (a.b.test), type A, class IN.
    fn query_bytes(flags: u16, counts: [u16; 3], class: u16) -> Vec<u8> {
        let mut m = vec![0xab, 0xcd];
        m.extend_from_slice(&flags.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        for c in counts {
            m.extend_from_slice(&c.to_be_bytes());
        }
        m.extend_from_slice(b"\x01a\x01b\x04test\x00\x00\x01");
        m.extend_from_slice(&class.to_be_bytes());
        m
    }

    #[test]
    fn plain_queries_need_sane_flags() {
        let ok = |m: &[u8]| dns(m).is_some_and(|d| d.is_plain_query());
        // RD set, one question, EDNS OPT in the additional section.
        assert!(ok(&query_bytes(0x0100, [0, 0, 0], 1)));
        assert!(ok(&query_bytes(0x0120, [0, 0, 1], 1))); // AD bit and an OPT record
        // Responses, other opcodes, flags no query carries, records in a query.
        assert!(!ok(&query_bytes(0x8100, [0, 0, 0], 1)));
        assert!(!ok(&query_bytes(0x2800, [0, 0, 0], 1))); // UPDATE
        assert!(!ok(&query_bytes(0x0500, [0, 0, 0], 1))); // AA
        assert!(!ok(&query_bytes(0x0300, [0, 0, 0], 1))); // TC
        assert!(!ok(&query_bytes(0x0180, [0, 0, 0], 1))); // RA
        assert!(!ok(&query_bytes(0x0140, [0, 0, 0], 1))); // Z
        assert!(!ok(&query_bytes(0x0103, [0, 0, 0], 1))); // rcode in a query
        assert!(!ok(&query_bytes(0x0100, [1, 0, 0], 1)));
        assert!(!ok(&query_bytes(0x0100, [0, 1, 0], 1)));
        assert!(!ok(&query_bytes(0x0100, [0, 0, 9], 1)));
        assert!(!ok(&query_bytes(0x0100, [0, 0, 0], 7))); // no such class
        // Garbage, too short, or a name that runs off the end.
        assert!(!ok(&[0u8; 40]));
        assert!(!ok(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n"));
        assert!(!ok(&query_bytes(0x0100, [0, 0, 0], 1)[..14]));
    }

    #[test]
    fn tls_sni_and_alpn() {
        let sni = b"api.example.org";
        let mut ext = Vec::new();
        ext.extend_from_slice(&[0, 0]);
        ext.extend_from_slice(&((sni.len() + 5) as u16).to_be_bytes());
        ext.extend_from_slice(&((sni.len() + 3) as u16).to_be_bytes());
        ext.push(0);
        ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        ext.extend_from_slice(sni);
        ext.extend_from_slice(&[0, 16, 0, 5, 0, 3, 2, b'h', b'2']);
        let mut hello = vec![3, 3];
        hello.extend_from_slice(&[0; 32]);
        hello.push(0); // session id
        hello.extend_from_slice(&[0, 2, 0x13, 0x01]); // one cipher suite
        hello.extend_from_slice(&[1, 0]); // null compression
        hello.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hello.extend_from_slice(&ext);
        let mut rec = vec![0x16, 3, 1];
        rec.extend_from_slice(&((hello.len() + 4) as u16).to_be_bytes());
        rec.extend_from_slice(&[1, 0]);
        rec.extend_from_slice(&(hello.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hello);
        let (s, a) = tls_client_hello(&rec).unwrap();
        assert_eq!(s.as_deref(), Some("api.example.org"));
        assert_eq!(a.as_deref(), Some("h2"));
    }

    #[test]
    fn http_and_ssh() {
        let mut m = AppMeta::default();
        m.absorb(
            b"GET /wp-login.php HTTP/1.1\r\nHost: example.com\r\nUser-Agent: zgrab/0.x\r\n\r\n",
            true,
        );
        assert_eq!(
            (m.proto, m.http_host.as_deref(), m.user_agent.as_deref()),
            (Some("http"), Some("example.com"), Some("zgrab/0.x"))
        );
        m.absorb(b"HTTP/1.1 404 Not Found\r\nServer: nginx\r\n\r\n", false);
        assert_eq!(
            (m.http_status, m.server.as_deref()),
            (Some(404), Some("nginx"))
        );

        let mut s = AppMeta::default();
        s.absorb(b"SSH-2.0-libssh_0.9.6\r\n", true);
        s.absorb(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n", false);
        assert_eq!(s.ssh_client.as_deref(), Some("SSH-2.0-libssh_0.9.6"));
        assert_eq!(
            s.ssh_server.as_deref(),
            Some("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13")
        );
    }
}
