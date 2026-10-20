//! Finite Zstandard streams retain the same buffered source across every frame.

use std::io::{self, BufRead, BufReader, Chain, Cursor, Read};

use ruzstd::decoding::{FrameDecoder, StreamingDecoder};

type Frame<R> = StreamingDecoder<Chain<Cursor<[u8; 4]>, BufReader<R>>, FrameDecoder>;

pub(crate) fn is_zstd_magic(magic: &[u8]) -> bool {
    magic.len() >= 4
        && (magic[..4] == [0x28, 0xb5, 0x2f, 0xfd]
            || (magic[0] & 0xf0 == 0x50 && magic[1..4] == [0x2a, 0x4d, 0x18]))
}

pub(crate) struct MultiZstdDecoder<R: Read> {
    source: Option<BufReader<R>>,
    frame: Option<Frame<R>>,
    decoder: Option<FrameDecoder>,
}

impl<R: Read> MultiZstdDecoder<R> {
    pub(crate) fn new(source: R) -> Self {
        Self {
            source: Some(BufReader::new(source)),
            frame: None,
            decoder: Some(FrameDecoder::new()),
        }
    }
}

impl<R: Read> Read for MultiZstdDecoder<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        loop {
            if let Some(frame) = self.frame.as_mut() {
                let count = frame.read(output)?;
                if count != 0 {
                    return Ok(count);
                }
                if let Some(frame) = self.frame.take() {
                    let (source, decoder) = frame.into_parts();
                    let (_, source) = source.into_inner();
                    self.source = Some(source);
                    self.decoder = Some(decoder);
                }
            }
            let mut source = self
                .source
                .take()
                .ok_or_else(|| io::Error::other("missing Zstandard frame source"))?;
            if source.fill_buf()?.is_empty() {
                self.source = Some(source);
                return Ok(0);
            }
            let mut magic = [0; 4];
            source.read_exact(&mut magic)?;
            if magic[0] & 0xf0 == 0x50 && magic[1..] == [0x2a, 0x4d, 0x18] {
                let mut length = [0; 4];
                source.read_exact(&mut length)?;
                let mut remaining = u64::from(u32::from_le_bytes(length));
                let mut scratch = [0; 8192];
                while remaining != 0 {
                    let count = remaining.min(scratch.len() as u64) as usize;
                    source.read_exact(&mut scratch[..count])?;
                    remaining -= count as u64;
                }
                self.source = Some(source);
                continue;
            }
            if magic != [0x28, 0xb5, 0x2f, 0xfd] {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid trailing Zstandard frame magic",
                ));
            }
            // Reuse the frame allocation without raising its default 128 MiB window cap.
            let decoder = self
                .decoder
                .take()
                .ok_or_else(|| io::Error::other("missing Zstandard frame decoder"))?;
            self.frame = Some(
                StreamingDecoder::new_with_decoder(Cursor::new(magic).chain(source), decoder)
                    .map_err(io::Error::other)?,
            );
        }
    }
}

#[cfg(test)]
pub(crate) fn raw_frame(bytes: &[u8]) -> Vec<u8> {
    assert!(bytes.len() < 128 * 1024);
    let mut frame = vec![0x28, 0xb5, 0x2f, 0xfd, 0xa0];
    frame.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    let header = ((bytes.len() as u32) << 3) | 1;
    frame.extend_from_slice(&header.to_le_bytes()[..3]);
    frame.extend_from_slice(bytes);
    frame
}

#[cfg(test)]
pub(crate) fn skippable_frame(bytes: &[u8]) -> Vec<u8> {
    let mut frame = vec![0x50, 0x2a, 0x4d, 0x18];
    frame.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    frame.extend_from_slice(bytes);
    frame
}
