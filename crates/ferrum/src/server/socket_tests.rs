#![allow(clippy::expect_used)]

use super::TimedIo;
use std::{io, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream},
};

async fn sockets() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener");
    let socket = TcpSocket::new_v4().expect("client socket");
    socket
        .set_send_buffer_size(4096)
        .expect("bounded send buffer");
    let writer = socket
        .connect(listener.local_addr().expect("listener address"))
        .await
        .expect("connect");
    let (reader, _) = listener.accept().await.expect("accept");

    (writer, reader)
}

#[tokio::test]
async fn scatter_gather_preserves_bytes_across_partial_writes() {
    let (writer, mut reader) = sockets().await;
    let mut writer = TimedIo::new(writer, Duration::from_secs(2));
    let first = vec![0x35; 256 * 1024];
    let second = vec![0xa7; 256 * 1024];
    let expected = [first.as_slice(), second.as_slice()].concat();
    let receive = tokio::spawn(async move {
        let mut received = Vec::new();
        let mut buffer = [0; 3071];

        loop {
            let length = reader.read(&mut buffer).await.expect("socket read");

            if length == 0 {
                break;
            }

            received.extend_from_slice(&buffer[..length]);
            tokio::task::yield_now().await;
        }

        received
    });
    let mut buffers = [io::IoSlice::new(&first), io::IoSlice::new(&second)];
    let mut remaining = buffers.as_mut_slice();

    tokio::time::timeout(Duration::from_secs(10), async {
        while !remaining.is_empty() {
            let written = writer
                .write_vectored(remaining)
                .await
                .expect("progressing scatter-gather write");
            assert_ne!(written, 0, "nonempty write must make progress");
            io::IoSlice::advance_slices(&mut remaining, written);
        }

        writer.shutdown().await.expect("writer shutdown");
    })
    .await
    .expect("bounded transfer");

    assert_eq!(receive.await.expect("receiver task"), expected);
}

#[tokio::test]
async fn stalled_scatter_gather_writer_releases_after_idle_timeout() {
    let (writer, _reader) = sockets().await;
    let mut writer = TimedIo::new(writer, Duration::from_millis(50));
    let bytes = vec![0x5a; 64 * 1024];
    let buffers = [io::IoSlice::new(&bytes), io::IoSlice::new(&bytes)];

    let error = tokio::time::timeout(Duration::from_secs(5), async {
        let mut sent = 0;

        loop {
            match writer.write_vectored(&buffers).await {
                Ok(length) => {
                    assert_ne!(length, 0, "nonempty write must make progress");
                    sent += length;
                    assert!(sent <= 64 * 1024 * 1024, "unread socket must backpressure");
                }
                Err(error) => break error,
            }
        }
    })
    .await
    .expect("idle timer must wake a stalled writer");

    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
}
