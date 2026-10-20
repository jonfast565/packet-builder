//! Minimal capture-file support: reading classic pcap (either byte order,
//! microsecond or nanosecond timestamps) and pcapng (enhanced and simple
//! packet blocks), and writing classic pcap.

/// One captured frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Link-layer type (1 = Ethernet, 147..=162 = user types, ...).
    pub linktype: u32,
    /// The captured bytes (possibly shorter than the frame on the wire).
    pub data: Vec<u8>,
}

/// Link type of Ethernet frames.
pub const LINKTYPE_ETHERNET: u32 = 1;
/// The first of the user-defined link types (`DLT_USER0`).
pub const LINKTYPE_USER0: u32 = 147;

/// Read every frame of a pcap or pcapng file.
pub fn read(file: &[u8]) -> Result<Vec<Frame>, String> {
    match file.get(..4) {
        Some([0x0a, 0x0d, 0x0d, 0x0a]) => read_pcapng(file),
        Some(_) => read_pcap(file),
        None => Err("not a capture file: too short".into()),
    }
}

/// A classic pcap file of `frames`, all with `linktype`.
pub fn write(linktype: u32, frames: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes()); // magic: microsecond timestamps
    out.extend_from_slice(&2u16.to_le_bytes()); // version 2.4
    out.extend_from_slice(&4u16.to_le_bytes());
    for v in [0u32, 0, 0x0004_0000, linktype] {
        // thiszone, sigfigs, snaplen, link type
        out.extend_from_slice(&v.to_le_bytes());
    }
    for (i, f) in frames.iter().enumerate() {
        let len = f.len() as u32;
        for v in [i as u32, 0, len, len] {
            // seconds, microseconds, captured length, original length
            out.extend_from_slice(&v.to_le_bytes());
        }
        out.extend_from_slice(f);
    }
    out
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
    big: bool,
}

impl<'a> Cursor<'a> {
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.pos.checked_add(n).filter(|e| *e <= self.data.len());
        let end = end.ok_or_else(|| format!("capture file truncated at byte {}", self.pos))?;
        let b = &self.data[self.pos..end];
        self.pos = end;
        Ok(b)
    }

    fn u16(&mut self) -> Result<u16, String> {
        let b: [u8; 2] = self.bytes(2)?.try_into().expect("2 bytes");
        Ok(if self.big { u16::from_be_bytes(b) } else { u16::from_le_bytes(b) })
    }

    fn u32(&mut self) -> Result<u32, String> {
        let b: [u8; 4] = self.bytes(4)?.try_into().expect("4 bytes");
        Ok(if self.big { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) })
    }

    fn done(&self) -> bool {
        self.pos >= self.data.len()
    }
}

fn read_pcap(file: &[u8]) -> Result<Vec<Frame>, String> {
    let magic = u32::from_le_bytes(file[..4].try_into().expect("4 bytes"));
    let big = match magic {
        0xa1b2c3d4 | 0xa1b23c4d => false,
        0xd4c3b2a1 | 0x4d3cb2a1 => true,
        _ => return Err("not a pcap or pcapng file (unknown magic number)".into()),
    };
    let mut c = Cursor { data: file, pos: 4, big };
    c.bytes(16)?; // version, thiszone, sigfigs, snaplen
    let linktype = c.u32()? & 0x0fff_ffff;
    let mut frames = Vec::new();
    while !c.done() {
        c.bytes(8)?; // timestamp
        let caplen = c.u32()? as usize;
        c.u32()?; // original length
        frames.push(Frame { linktype, data: c.bytes(caplen)?.to_vec() });
    }
    Ok(frames)
}

fn read_pcapng(file: &[u8]) -> Result<Vec<Frame>, String> {
    let mut c = Cursor { data: file, pos: 0, big: false };
    let mut interfaces: Vec<u32> = Vec::new();
    let mut frames = Vec::new();
    while !c.done() {
        let start = c.pos;
        let kind = c.u32()?;
        if kind == 0x0a0d0d0a {
            // Section header: the byte-order magic decides the endianness.
            let len_raw: [u8; 4] = c.bytes(4)?.try_into().expect("4 bytes");
            let bom = c.bytes(4)?;
            c.big = bom == [0x1a, 0x2b, 0x3c, 0x4d];
            let len = if c.big { u32::from_be_bytes(len_raw) } else { u32::from_le_bytes(len_raw) } as usize;
            interfaces.clear();
            c.pos = start;
            c.bytes(len.max(12))?;
            continue;
        }
        let len = c.u32()? as usize;
        if len < 12 {
            return Err(format!("invalid pcapng block length {} at byte {}", len, start));
        }
        let body_end = start + len - 4;
        match kind {
            1 => {
                // Interface description: link type, reserved, snaplen.
                interfaces.push(c.u16()? as u32);
            }
            6 => {
                // Enhanced packet: interface, timestamp (2 x u32), captured, original.
                let iface = c.u32()? as usize;
                c.bytes(8)?;
                let caplen = c.u32()? as usize;
                c.u32()?;
                let linktype = *interfaces.get(iface).ok_or("packet refers to an unknown interface")?;
                frames.push(Frame { linktype, data: c.bytes(caplen)?.to_vec() });
            }
            3 => {
                // Simple packet: original length, then the data up to the block end.
                c.u32()?;
                let linktype = *interfaces.first().ok_or("packet before any interface")?;
                let n = body_end.checked_sub(c.pos).ok_or("invalid simple packet block")?;
                frames.push(Frame { linktype, data: c.bytes(n)?.to_vec() });
            }
            _ => {}
        }
        c.pos = start;
        c.bytes(len)?;
    }
    Ok(frames)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcap_round_trip() {
        let frames = vec![vec![1, 2, 3], vec![], vec![0xff; 70]];
        let file = write(LINKTYPE_USER0, &frames);
        let back = read(&file).unwrap();
        assert_eq!(back.len(), 3);
        assert!(back.iter().all(|f| f.linktype == LINKTYPE_USER0));
        assert_eq!(back.iter().map(|f| f.data.clone()).collect::<Vec<_>>(), frames);
    }

    #[test]
    fn pcapng_enhanced_packets() {
        let mut f = Vec::new();
        let block = |f: &mut Vec<u8>, kind: u32, body: &[u8]| {
            let len = (12 + body.len()) as u32;
            f.extend_from_slice(&kind.to_le_bytes());
            f.extend_from_slice(&len.to_le_bytes());
            f.extend_from_slice(body);
            f.extend_from_slice(&len.to_le_bytes());
        };
        let mut shb = vec![0x4d, 0x3c, 0x2b, 0x1a, 1, 0, 0, 0];
        shb.extend_from_slice(&u64::MAX.to_le_bytes());
        block(&mut f, 0x0a0d0d0a, &shb);
        block(&mut f, 1, &[1, 0, 0, 0, 0, 0, 0, 0]);
        let mut epb = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 3, 0, 0, 0];
        epb.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0]);
        block(&mut f, 6, &epb);
        let frames = read(&f).unwrap();
        assert_eq!(frames, vec![Frame { linktype: 1, data: vec![0xaa, 0xbb, 0xcc] }]);
    }

    #[test]
    fn truncated_files_are_errors() {
        let file = write(1, &[vec![1, 2, 3, 4]]);
        assert!(read(&file[..file.len() - 1]).is_err());
        assert!(read(&[0, 1]).is_err());
    }
}
