//! The content hashes cloud providers report, computed over the bytes as they
//! arrive, so the copy can be checked against the provider's own record:
//! MD5 and SHA-1 (Google Drive, S3 single-part ETags, Box, …), OneDrive and
//! SharePoint's QuickXorHash, and Dropbox's content hash. Names as rclone
//! reports them in `lsjson --hash`.

use sha2::Digest;

/// Microsoft's QuickXorHash: a 160-bit XOR of the input shifted by 11 bits
/// per byte, with the length XORed into the last 8 bytes
pub struct QuickXor {
    data: [u64; 3],
    length: u64,
    shift: usize,
}

const WIDTH: usize = 160;
const SHIFT: usize = 11;
const LAST_CELL_BITS: usize = WIDTH % 64;

impl Default for QuickXor {
    fn default() -> Self {
        Self::new()
    }
}

impl QuickXor {
    pub fn new() -> Self {
        Self {
            data: [0; 3],
            length: 0,
            shift: 0,
        }
    }

    pub fn update(&mut self, bytes: &[u8]) {
        let mut index = self.shift / 64;
        let mut offset = self.shift % 64;
        let iterations = bytes.len().min(WIDTH);
        for i in 0..iterations {
            let last = index == self.data.len() - 1;
            let cell_bits = if last { LAST_CELL_BITS } else { 64 };
            if offset + 8 <= cell_bits {
                let mut j = i;
                while j < bytes.len() {
                    self.data[index] ^= u64::from(bytes[j]) << offset;
                    j += WIDTH;
                }
            } else {
                let next = if last { 0 } else { index + 1 };
                let low = cell_bits - offset;
                let mut xored = 0u8;
                let mut j = i;
                while j < bytes.len() {
                    xored ^= bytes[j];
                    j += WIDTH;
                }
                self.data[index] ^= u64::from(xored) << offset;
                self.data[next] ^= u64::from(xored) >> low;
            }
            offset += SHIFT;
            while offset >= cell_bits {
                index = if last { 0 } else { index + 1 };
                offset -= cell_bits;
            }
        }
        self.shift = (self.shift + SHIFT * (bytes.len() % WIDTH)) % WIDTH;
        self.length = self.length.wrapping_add(bytes.len() as u64);
    }

    pub fn finish(&self) -> [u8; 20] {
        let mut out = [0u8; 20];
        out[..8].copy_from_slice(&self.data[0].to_le_bytes());
        out[8..16].copy_from_slice(&self.data[1].to_le_bytes());
        out[16..].copy_from_slice(&self.data[2].to_le_bytes()[..4]);
        for (i, b) in self.length.to_le_bytes().iter().enumerate() {
            out[20 - 8 + i] ^= b;
        }
        out
    }
}

/// Dropbox's content hash: SHA-256 over the SHA-256 of every 4 MiB block
pub struct DropboxHash {
    outer: sha2::Sha256,
    block: sha2::Sha256,
    in_block: usize,
}

const BLOCK: usize = 4 << 20;

impl Default for DropboxHash {
    fn default() -> Self {
        Self::new()
    }
}

impl DropboxHash {
    pub fn new() -> Self {
        Self {
            outer: sha2::Sha256::new(),
            block: sha2::Sha256::new(),
            in_block: 0,
        }
    }

    pub fn update(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let take = (BLOCK - self.in_block).min(bytes.len());
            self.block.update(&bytes[..take]);
            self.in_block += take;
            bytes = &bytes[take..];
            if self.in_block == BLOCK {
                let done = std::mem::take(&mut self.block).finalize();
                self.outer.update(done);
                self.in_block = 0;
            }
        }
    }

    pub fn finish(mut self) -> [u8; 32] {
        if self.in_block > 0 {
            self.outer.update(self.block.finalize());
        }
        self.outer.finalize().into()
    }
}

/// One of the hashes a provider reports, computed alongside the copy
pub enum Provider {
    Md5(md5::Md5),
    Sha1(sha1::Sha1),
    QuickXor(QuickXor),
    Dropbox(Box<DropboxHash>),
}

impl Provider {
    /// For an rclone hash name; `None` for kinds dfcollect doesn't compute
    pub fn for_name(name: &str) -> Option<Self> {
        Some(match name {
            "md5" => Provider::Md5(md5::Md5::new()),
            "sha1" => Provider::Sha1(sha1::Sha1::new()),
            "quickxor" => Provider::QuickXor(QuickXor::new()),
            "dropbox" => Provider::Dropbox(Box::default()),
            _ => return None,
        })
    }

    pub fn update(&mut self, bytes: &[u8]) {
        match self {
            Provider::Md5(h) => h.update(bytes),
            Provider::Sha1(h) => h.update(bytes),
            Provider::QuickXor(h) => h.update(bytes),
            Provider::Dropbox(h) => h.update(bytes),
        }
    }

    /// Lower-case hex, as rclone prints it
    pub fn finish(self) -> String {
        let bytes: Vec<u8> = match self {
            Provider::Md5(h) => h.finalize().to_vec(),
            Provider::Sha1(h) => h.finalize().to_vec(),
            Provider::QuickXor(h) => h.finish().to_vec(),
            Provider::Dropbox(h) => h.finish().to_vec(),
        };
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn ramp() -> Vec<u8> {
        (0..1000u32).map(|i| ((i * 7 + 3) % 256) as u8).collect()
    }

    fn big() -> Vec<u8> {
        (0..9 * 1024 * 1024 + 123u32)
            .map(|i| ((u64::from(i) * 31 + 17) % 251) as u8)
            .collect()
    }

    /// Values from `rclone hashsum quickxor|dropbox` (rclone v1.75.1)
    #[test]
    fn quickxor_matches_rclone() {
        let q = |data: &[u8], chunk: usize| {
            let mut h = QuickXor::new();
            for c in data.chunks(chunk.max(1)) {
                h.update(c);
            }
            hex(&h.finish())
        };
        assert_eq!(q(b"", 1), "0000000000000000000000000000000000000000");
        assert_eq!(q(b"hello", 1), "6828031bd8f00600000000000500000000000000");
        assert_eq!(q(b"hello", 5), "6828031bd8f00600000000000500000000000000");
        for chunk in [1, 7, 160, 333, 1000] {
            assert_eq!(
                q(&ramp(), chunk),
                "7600fc8f49fcb0cd1a3c4e42509f2daa68a55ff1",
                "chunk {chunk}"
            );
        }
        assert_eq!(
            q(&big(), 1 << 20),
            "567505cc59c8d77664fbcca19d79a69d6361523d"
        );
        assert_eq!(
            q(&big(), 65_537),
            "567505cc59c8d77664fbcca19d79a69d6361523d"
        );
    }

    #[test]
    fn dropbox_matches_rclone() {
        let d = |data: &[u8], chunk: usize| {
            let mut h = DropboxHash::new();
            for c in data.chunks(chunk.max(1)) {
                h.update(c);
            }
            hex(&h.finish())
        };
        assert_eq!(
            d(b"", 1),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            d(b"hello", 2),
            "9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50"
        );
        assert_eq!(
            d(&ramp(), 64),
            "f75824a4950624d8c81364a1fd4ffa23dce7d0c3d3493372b330878c8ae29422"
        );
        assert_eq!(
            d(&big(), 1 << 20),
            "70dbedf144e43b1d43da247ff2715d10b238724b768c2fb57582e5a426a85b6f"
        );
        assert_eq!(
            d(&big(), 3_000_001),
            "70dbedf144e43b1d43da247ff2715d10b238724b768c2fb57582e5a426a85b6f"
        );
    }

    #[test]
    fn providers_by_name() {
        let mut p = Provider::for_name("md5").unwrap();
        p.update(b"hello");
        assert_eq!(p.finish(), "5d41402abc4b2a76b9719d911017c592");
        assert!(Provider::for_name("whirlpool").is_none());
    }
}
