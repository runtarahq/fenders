//! Authenticated-frame reader. Consumers must read through EOF and call finish
//! before treating an archive as complete; earlier frames are not a whole backup.
use super::*;

pub(crate) struct DecryptReader<R> {
    source: R,
    cipher: Aes256Gcm,
    header: Vec<u8>,
    plain: Vec<u8>,
    offset: usize,
    index: u32,
    total: u64,
    limit: u64,
    done: bool,
    failed: bool,
    authentication_failed: bool,
}
fn invalid() -> io::Error {
    io::Error::other("invalid or incomplete authenticated backup stream")
}
impl<R: Read> DecryptReader<R> {
    pub(crate) fn new(mut source: R, key: &[u8; 32], limit: u64) -> Result<Self> {
        let mut header = vec![0; MAGIC.len() + 32];
        source.read_exact(&mut header)?;
        if !header.starts_with(MAGIC) {
            return Err(invalid().into());
        }
        let cipher = cipher(key, &header[MAGIC.len()..])?;
        Ok(Self {
            source,
            cipher,
            header,
            plain: Vec::new(),
            offset: 0,
            index: 0,
            total: 0,
            limit,
            done: false,
            failed: false,
            authentication_failed: false,
        })
    }
    fn frame(&mut self) -> io::Result<()> {
        self.plain.fill(0);
        self.plain.clear();
        self.offset = 0;
        let mut length = [0; 4];
        self.source.read_exact(&mut length)?;
        let length = u32::from_be_bytes(length) as usize;
        if !(16..=CHUNK + 16).contains(&length) {
            return Err(invalid());
        }
        let mut encrypted = vec![0; length];
        self.source.read_exact(&mut encrypted)?;
        let counter = self.index.to_be_bytes();
        let mut nonce = [0; 12];
        nonce[8..].copy_from_slice(&counter);
        let mut aad = self.header.clone();
        aad.extend_from_slice(&counter);
        let plain = self
            .cipher
            .decrypt(
                (&nonce).into(),
                Payload {
                    msg: &encrypted,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                self.authentication_failed = true;
                invalid()
            })?;
        if plain.is_empty() {
            if self.source.read(&mut [0; 1])? != 0 {
                return Err(invalid());
            }
            self.done = true;
            return Ok(());
        }
        self.total = self
            .total
            .checked_add(plain.len() as u64)
            .filter(|n| *n <= self.limit)
            .ok_or_else(invalid)?;
        self.index = self.index.checked_add(1).ok_or_else(invalid)?;
        self.plain = plain;
        Ok(())
    }
    pub(crate) fn finish(self) -> Result<(R, u64)> {
        if self.failed || !self.done || self.offset != self.plain.len() {
            return Err(invalid().into());
        }
        Ok((self.source, self.total))
    }
    /// Distinguish an actual AEAD failure from I/O, truncation, limits and
    /// cancellation. Recovery must never treat those other errors as consent
    /// to overwrite a complete candidate.
    #[cfg(test)]
    fn authentication_failed(&self) -> bool {
        self.authentication_failed
    }
}
impl<R: Read> Read for DecryptReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.failed {
            return Err(invalid());
        }
        if self.offset == self.plain.len()
            && !self.done
            && let Err(error) = self.frame()
        {
            self.failed = true;
            self.plain.fill(0);
            self.plain.clear();
            return Err(error);
        }
        let n = out.len().min(self.plain.len() - self.offset);
        out[..n].copy_from_slice(&self.plain[self.offset..self.offset + n]);
        self.offset += n;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn encrypted(bytes: &[u8]) -> Vec<u8> {
        let mut writer = EncryptWriter::new(Vec::new(), &[7; 32], u64::MAX).unwrap();
        writer.write_all(bytes).unwrap();
        writer.finish().unwrap().0
    }
    #[test]
    fn reads_authenticated_frames_incrementally_and_requires_consumed_eof() {
        for size in [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, CHUNK * 2] {
            let bytes = vec![42; size];
            let encrypted = encrypted(&bytes);
            let mut reader =
                DecryptReader::new(encrypted.as_slice(), &[7; 32], size as u64).unwrap();
            let mut out = vec![];
            let mut buffer = [0; 1301];
            loop {
                let n = reader.read(&mut buffer).unwrap();
                if n == 0 {
                    break;
                }
                out.extend_from_slice(&buffer[..n]);
            }
            assert_eq!(out, bytes);
            assert_eq!(reader.finish().unwrap().1, size as u64);
            let reader = DecryptReader::new(encrypted.as_slice(), &[7; 32], size as u64).unwrap();
            assert!(reader.finish().is_err());
        }
        let bytes = encrypted(b"payload");
        let mut reader = DecryptReader::new(bytes.as_slice(), &[7; 32], 7).unwrap();
        reader.read_exact(&mut [0; 7]).unwrap();
        // Consuming all requested payload bytes is still not observing the final
        // authenticated marker or EOF; completion must remain unproven.
        assert!(reader.finish().is_err());
    }
    #[test]
    fn refuses_bad_authentication_truncation_extra_bytes_and_plaintext_limit() {
        let encrypted = encrypted(&vec![42; CHUNK + 10]);
        let mut cases = vec![];
        for cut in [1, 16, 20, 30] {
            cases.push(encrypted[..encrypted.len() - cut].to_vec());
        }
        let mut wrong = encrypted.clone();
        wrong[MAGIC.len() + 3] ^= 1;
        cases.push(wrong);
        let mut wrong = encrypted.clone();
        wrong[MAGIC.len() + 32 + 4 + 10] ^= 1;
        cases.push(wrong);
        let mut extra = encrypted.clone();
        extra.push(0);
        cases.push(extra);
        let mut duplicate = encrypted.clone();
        duplicate.extend_from_slice(&encrypted);
        cases.push(duplicate);
        for bytes in cases {
            let mut reader = DecryptReader::new(bytes.as_slice(), &[7; 32], u64::MAX).unwrap();
            assert!(io::copy(&mut reader, &mut io::sink()).is_err());
            assert!(reader.read(&mut [0; 1]).is_err());
            assert!(reader.finish().is_err());
        }
        for (key, limit) in [([8; 32], u64::MAX), ([7; 32], CHUNK as u64)] {
            let mut reader = DecryptReader::new(encrypted.as_slice(), &key, limit).unwrap();
            assert!(io::copy(&mut reader, &mut io::sink()).is_err());
            assert!(reader.finish().is_err());
        }
    }
    #[test]
    fn only_aead_failures_are_classified_as_corruption() {
        let original = encrypted(b"payload");
        let header = MAGIC.len() + 32;
        for terminal in [false, true] {
            let mut damaged = original.clone();
            let offset = if terminal {
                damaged.len() - 1
            } else {
                header + 4
            };
            damaged[offset] ^= 1;
            let mut reader = DecryptReader::new(damaged.as_slice(), &[7; 32], 7).unwrap();
            assert!(io::copy(&mut reader, &mut io::sink()).is_err());
            assert!(reader.authentication_failed());
            assert!(reader.finish().is_err());
        }
        for (bytes, limit) in [
            (&original[..original.len() - 1], 7),
            (original.as_slice(), 6),
        ] {
            let mut reader = DecryptReader::new(bytes, &[7; 32], limit).unwrap();
            assert!(io::copy(&mut reader, &mut io::sink()).is_err());
            assert!(!reader.authentication_failed());
        }
        struct ReadFailure<'a>(&'a [u8]);
        impl Read for ReadFailure<'_> {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                if self.0.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "injected storage failure",
                    ));
                }
                self.0.read(out)
            }
        }
        let mut reader =
            DecryptReader::new(ReadFailure(&original[..header + 4]), &[7; 32], 7).unwrap();
        assert_eq!(
            io::copy(&mut reader, &mut io::sink()).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(!reader.authentication_failed());
        let mut reader = DecryptReader::new(original.as_slice(), &[7; 32], 7).unwrap();
        io::copy(&mut reader, &mut io::sink()).unwrap();
        assert!(!reader.authentication_failed());
        reader.finish().unwrap();
    }
}
