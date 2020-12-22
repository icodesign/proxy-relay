#[cfg(feature = "native-tls")]
pub mod native_tls_conn {
    use bytes::{Buf, BufMut};
    use pin_project_lite::pin_project;
    use std::mem::MaybeUninit;
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };
    use tokio::io::{AsyncRead, AsyncWrite};
    use tokio_tls::TlsStream;

    pin_project! {
        pub(super) struct NativeTlsConn<T> {
            #[pin] pub(super) inner: TlsStream<T>,
        }
    }

    impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for NativeTlsConn<T> {
        unsafe fn prepare_uninitialized_buffer(&self, buf: &mut [MaybeUninit<u8>]) -> bool {
            self.inner.prepare_uninitialized_buffer(buf)
        }

        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &mut [u8],
        ) -> Poll<tokio::io::Result<usize>> {
            let this = self.project();
            AsyncRead::poll_read(this.inner, cx, buf)
        }

        fn poll_read_buf<B: BufMut>(
            self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &mut B,
        ) -> Poll<tokio::io::Result<usize>>
        where
            Self: Sized,
        {
            let this = self.project();
            AsyncRead::poll_read_buf(this.inner, cx, buf)
        }
    }

    impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for NativeTlsConn<T> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &[u8],
        ) -> Poll<Result<usize, tokio::io::Error>> {
            let this = self.project();
            AsyncWrite::poll_write(this.inner, cx, buf)
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            cx: &mut Context,
        ) -> Poll<Result<(), tokio::io::Error>> {
            let this = self.project();
            AsyncWrite::poll_flush(this.inner, cx)
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            cx: &mut Context,
        ) -> Poll<Result<(), tokio::io::Error>> {
            let this = self.project();
            AsyncWrite::poll_shutdown(this.inner, cx)
        }

        fn poll_write_buf<B: Buf>(
            self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &mut B,
        ) -> Poll<Result<usize, tokio::io::Error>>
        where
            Self: Sized,
        {
            let this = self.project();
            AsyncWrite::poll_write_buf(this.inner, cx, buf)
        }
    }
}

#[cfg(feature = "rustls")]
pub mod rustls_tls_conn {
    use bytes::{Buf, BufMut};
    use pin_project_lite::pin_project;
    use std::mem::MaybeUninit;
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };
    use tokio::io::{AsyncRead, AsyncWrite};
    use tokio_rustls::client::TlsStream;

    pin_project! {
        pub(super) struct RustlsTlsConn<T> {
            #[pin] pub(super) inner: TlsStream<T>,
        }
    }

    impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for RustlsTlsConn<T> {
        unsafe fn prepare_uninitialized_buffer(&self, buf: &mut [MaybeUninit<u8>]) -> bool {
            self.inner.prepare_uninitialized_buffer(buf)
        }

        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &mut [u8],
        ) -> Poll<tokio::io::Result<usize>> {
            let this = self.project();
            AsyncRead::poll_read(this.inner, cx, buf)
        }

        fn poll_read_buf<B: BufMut>(
            self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &mut B,
        ) -> Poll<tokio::io::Result<usize>>
        where
            Self: Sized,
        {
            let this = self.project();
            AsyncRead::poll_read_buf(this.inner, cx, buf)
        }
    }

    impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for RustlsTlsConn<T> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &[u8],
        ) -> Poll<Result<usize, tokio::io::Error>> {
            let this = self.project();
            AsyncWrite::poll_write(this.inner, cx, buf)
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            cx: &mut Context,
        ) -> Poll<Result<(), tokio::io::Error>> {
            let this = self.project();
            AsyncWrite::poll_flush(this.inner, cx)
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            cx: &mut Context,
        ) -> Poll<Result<(), tokio::io::Error>> {
            let this = self.project();
            AsyncWrite::poll_shutdown(this.inner, cx)
        }

        fn poll_write_buf<B: Buf>(
            self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &mut B,
        ) -> Poll<Result<usize, tokio::io::Error>>
        where
            Self: Sized,
        {
            let this = self.project();
            AsyncWrite::poll_write_buf(this.inner, cx, buf)
        }
    }
}
