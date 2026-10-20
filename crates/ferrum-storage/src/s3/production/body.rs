use super::*;
use aws_smithy_types::body::SdkBody;
use futures_util::Stream;
use http_body::{Body, Frame, SizeHint};
use std::pin::Pin;
use std::task::{Context, Poll};

pub(crate) fn object_body(
    object: &VerifiedObject,
    offset: u64,
    size: u64,
) -> Result<ByteStream, S3Error> {
    let end = offset.checked_add(size).ok_or(S3Error::Boundary)?;
    if end > object.size() {
        return Err(S3Error::Boundary);
    }
    if size == 0 {
        return Ok(ByteStream::from(Bytes::new()));
    }

    let stream = object
        .stream_range(offset, end - 1)
        .map_err(|_| S3Error::Boundary)?;
    Ok(ByteStream::new(SdkBody::from_body_1_x(ObjectBody {
        stream: Mutex::new(stream),
        remaining: size,
    })))
}

struct ObjectBody {
    // SdkBody requires Sync. Polling has exclusive access and does not lock.
    // The range and every detached read own the immutable object lease, unlike
    // SDK path bodies whose file reads can outlive the caller's lease.
    stream: Mutex<crate::ObjectStream>,
    remaining: u64,
}

impl Body for ObjectBody {
    type Data = Bytes;
    type Error = aws_smithy_types::body::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let stream = match self.stream.get_mut() {
            Ok(stream) => stream,
            Err(_) => {
                return Poll::Ready(Some(Err(std::io::Error::other(
                    "upload stream mutex poisoned",
                )
                .into())));
            }
        };

        match Pin::new(stream).poll_next(context) {
            Poll::Ready(Some(Ok(bytes))) => {
                self.remaining = self.remaining.saturating_sub(bytes.len() as u64);
                Poll::Ready(Some(Ok(Frame::data(bytes))))
            }
            Poll::Ready(Some(Err(error))) => {
                Poll::Ready(Some(Err(std::io::Error::other(error.to_string()).into())))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.remaining)
    }

    fn is_end_stream(&self) -> bool {
        self.remaining == 0
    }
}
