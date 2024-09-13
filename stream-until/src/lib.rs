//!
//! This create provides [StreamUntil], which wraps a [Stream] and a [Future].
//!
//! [StreamUntil] implements [Stream] and will yield items from the wrapped
//! stream until the wrapped future resolves. At that point, the future's
//! output will be yielded and the stream will end.
//!

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_core::Stream;

/// Item returned by [StreamUntil].
pub enum StreamUntilItem<S, F> {
	Stream(S),
	Future(F),
}

impl<S: Clone, F: Clone> Clone for StreamUntilItem<S, F> {
	fn clone(&self) -> Self {
		match self {
			Self::Stream(v) => Self::Stream(v.clone()),
			Self::Future(v) => Self::Future(v.clone()),
		}
	}
}

impl<S: fmt::Debug, F: fmt::Debug> fmt::Debug for StreamUntilItem<S, F> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			Self::Stream(v) => write!(f, "Stream({:?})", v),
			Self::Future(v) => write!(f, "Future({:?})", v),
		}
	}
}

/// A [Stream] that wraps a [Stream] and a [Future] and will yield items from
/// the stream until the future resolves.
///
/// As soon as [StreamUntilItem::Future] has been yielded, the stream will not
/// yield any more items.
pub struct StreamUntil<S: Stream, F: Future> {
	stream: S,
	future: F,
	done: bool,
}

impl<S: Stream, F: Future> StreamUntil<S, F> {
	/// Create a new [StreamUntil] from the given stream and future.
	pub fn new(stream: S, future: F) -> StreamUntil<S, F> {
		let done = false;
		StreamUntil { stream, future, done }
	}
}

impl<S: Stream + Unpin, F: Future + Unpin> Stream for StreamUntil<S, F> {
	type Item = StreamUntilItem<S::Item, F::Output>;

	fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		if self.done {
			return Poll::Ready(None);
		}

		if let Poll::Ready(val) = Pin::new(&mut self.future).poll(cx) {
			self.done = true;
			return Poll::Ready(Some(StreamUntilItem::Future(val)));
		}

		Pin::new(&mut self.stream)
			.poll_next(cx)
			.map(|v| v.map(StreamUntilItem::Stream))
	}
}

/// This [Stream] extension trait provides a [until] method that terminates the
/// stream once the given future resolves.
pub trait StreamExt: Stream {
	/// Yields elements from this stream until the given future resolves.
	fn until<F>(self, until: F) -> StreamUntil<Self, F>
	where
		F: Future,
		Self: Sized,
	{
		StreamUntil::new(self, until)
	}
}

impl<S: Stream> StreamExt for S {}

