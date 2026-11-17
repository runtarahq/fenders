//! Bounded streaming writer for the existing authenticated backup envelope.
//! A terminal authenticated empty frame distinguishes completion from truncation.
use super::*;
use std::io;
mod read;
pub(crate) use read::DecryptReader;

pub(crate) struct EncryptWriter<W> {
    out: W,
    cipher: Aes256Gcm,
    header: Vec<u8>,
    plain: Vec<u8>,
    index: u32,
    bytes: u64,
    limit: u64,
    hash: Sha256,
    failed: bool,
}
impl<W: Write> EncryptWriter<W> {
    pub(crate) fn new(out: W, key: &[u8; 32], limit: u64) -> Result<Self> {
        let mut salt = [0; 32];
        File::open("/dev/urandom")?.read_exact(&mut salt)?;
        Self::with_salt(out, key, limit, &salt)
    }
    /// Caller must durably consume a fresh salt before writing. Never resume a
    /// failed writer or reconstruct it with a previously admitted salt.
    pub(crate) fn with_salt(out: W, key: &[u8; 32], limit: u64, salt: &[u8; 32]) -> Result<Self> {
        let mut header = MAGIC.to_vec();
        header.extend_from_slice(salt);
        let mut this = Self {
            out,
            cipher: cipher(key, salt)?,
            header: header.clone(),
            plain: Vec::with_capacity(CHUNK),
            index: 0,
            bytes: 0,
            limit,
            hash: Sha256::new(),
            failed: false,
        };
        this.emit(&header)?;
        Ok(this)
    }
    fn emit(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.failed || bytes.len() as u64 > self.limit - self.bytes {
            self.failed = true;
            return Err(io::Error::other(
                "encrypted backup exceeds reserved output or writer failed",
            ));
        }
        if let Err(error) = self.out.write_all(bytes) {
            self.failed = true;
            return Err(error);
        }
        self.bytes += bytes.len() as u64;
        self.hash.update(bytes);
        Ok(())
    }
    fn frame(&mut self) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::other("backup writer failed"));
        }
        let Some(next) = self.index.checked_add(1) else {
            self.failed = true;
            return Err(io::Error::other("backup frame limit"));
        };
        let counter = self.index.to_be_bytes();
        let mut nonce = [0; 12];
        nonce[8..].copy_from_slice(&counter);
        let mut aad = self.header.clone();
        aad.extend_from_slice(&counter);
        let encrypted = self
            .cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: &self.plain,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                self.failed = true;
                io::Error::other("backup encryption failed")
            })?;
        // Check the entire frame before writing its length prefix.
        if encrypted.len() as u64 + 4 > self.limit - self.bytes {
            self.failed = true;
            return Err(io::Error::other("encrypted backup exceeds reserved output"));
        }
        self.emit(&(encrypted.len() as u32).to_be_bytes())?;
        self.emit(&encrypted)?;
        self.plain.fill(0);
        self.plain.clear();
        self.index = next;
        Ok(())
    }
    pub(crate) fn finish(mut self) -> Result<(W, u64, String)> {
        if !self.plain.is_empty() {
            self.frame()?;
        }
        self.frame()?;
        self.flush()?;
        Ok((self.out, self.bytes, format!("{:x}", self.hash.finalize())))
    }
}
impl<W: Write> Write for EncryptWriter<W> {
    fn write(&mut self, mut bytes: &[u8]) -> io::Result<usize> {
        if self.failed {
            return Err(io::Error::other("backup writer failed"));
        }
        let length = bytes.len();
        while !bytes.is_empty() {
            let n = bytes.len().min(CHUNK - self.plain.len());
            self.plain.extend_from_slice(&bytes[..n]);
            bytes = &bytes[n..];
            if self.plain.len() == CHUNK {
                self.frame()?;
            }
        }
        Ok(length)
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::other("backup writer failed"));
        }
        if let Err(error) = self.out.flush() {
            self.failed = true;
            return Err(error);
        }
        Ok(())
    }
}
use std::fs::File;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn streaming_envelope_roundtrips_at_chunk_boundaries_and_obeys_exact_budget() {
        let root = tempfile::tempdir().unwrap();
        for size in [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, CHUNK * 2] {
            let plain = vec![42; size];
            let key = [7; 32];
            let limit = (MAGIC.len() + 32 + 20 + size + size.div_ceil(CHUNK) * 20) as u64;
            let mut writer = EncryptWriter::new(Vec::new(), &key, limit).unwrap();
            for part in plain.chunks(1301) {
                writer.write_all(part).unwrap();
                writer.flush().unwrap();
            }
            let (bytes, count, hash) = writer.finish().unwrap();
            assert_eq!(count, limit);
            assert_eq!(hash, crate::model::digest(&bytes));
            let enc = root.path().join(format!("enc-{size}"));
            let dec = root.path().join(format!("dec-{size}"));
            fs::write(&enc, &bytes).unwrap();
            super::super::decrypt(&enc, &dec, &key, size as u64).unwrap();
            assert_eq!(fs::read(dec).unwrap(), plain);
            let mut too_small = EncryptWriter::new(Vec::new(), &key, limit - 1).unwrap();
            assert!(
                too_small
                    .write_all(&plain)
                    .and_then(|_| too_small
                        .finish()
                        .map(|_| ())
                        .map_err(|_| io::Error::other("limit")))
                    .is_err()
            );
        }
    }
    #[test]
    fn failed_writer_cannot_finish_or_retry_and_ciphertext_is_randomized() {
        let mut a = EncryptWriter::new(Vec::new(), &[4; 32], 1000).unwrap();
        a.write_all(b"message").unwrap();
        let (a, _, _) = a.finish().unwrap();
        let mut b = EncryptWriter::new(Vec::new(), &[4; 32], 1000).unwrap();
        b.write_all(b"message").unwrap();
        assert_ne!(a, b.finish().unwrap().0);
        let mut short = [0u8; 80];
        let mut writer = EncryptWriter::new(&mut short[..], &[4; 32], 10000).unwrap();
        writer.write_all(&[1; 100]).unwrap();
        assert!(writer.frame().is_err());
        assert!(writer.write_all(b"again").is_err());
        assert!(writer.finish().is_err());
        let mut exhausted = EncryptWriter::new(Vec::new(), &[4; 32], 10000).unwrap();
        exhausted.index = u32::MAX;
        assert!(exhausted.frame().is_err());
        assert!(exhausted.write_all(b"no nonce reuse").is_err());
        assert!(exhausted.finish().is_err());
    }
}
