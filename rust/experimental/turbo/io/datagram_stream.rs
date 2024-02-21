// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Datagram stream implementation
//!
//! The datagram stream consists of a btree of [`super::PartialDatagram`].

use super::PartialDatagram;

use crate::experimental::turbo::support::BTreeSet;

/// A stream of datagram.
pub(crate) struct DatagramStream<BTS>
where
    BTS: BTreeSet<PartialDatagram>,
{
    /// The actual stream.
    set: BTS,

    /// The index of the current incoming datagram we expect.
    index_in: std::cell::Cell<u8>,

    /// The position in the buffer of the incoming datagram we expect.
    dg_pos: std::cell::Cell<usize>,
}

unsafe impl<BTS> Send for DatagramStream<BTS> where BTS: BTreeSet<PartialDatagram> {}
unsafe impl<BTS> Sync for DatagramStream<BTS> where BTS: BTreeSet<PartialDatagram> {}

/// Implements [`Default`] for [`DatagramStream`].
impl<BTS> Default for DatagramStream<BTS>
where
    BTS: BTreeSet<PartialDatagram> + Default,
{
    fn default() -> Self {
        Self::new()
    }
}

/// Implements [`std::fmt::Debug`] for [`DatagramStream`].
impl<BTS> std::fmt::Debug for DatagramStream<BTS>
where
    BTS: BTreeSet<PartialDatagram>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "DatagramStream[count={}, index_in={}, dg_pos={:#x}]",
            self.set.len(),
            self.index_in.get(),
            self.dg_pos.get(),
        )
    }
}

/// Implements [`DatagramStream`].
impl<BTS> DatagramStream<BTS>
where
    BTS: BTreeSet<PartialDatagram> + Default,
{
    /// Instantiates a new [`DatagramStream`].
    pub(crate) fn new() -> Self {
        Self {
            set: BTS::default(),
            index_in: std::cell::Cell::new(1),
            dg_pos: std::cell::Cell::new(0),
        }
    }

    /// Reads from the queue.
    pub(crate) fn read(
        &self,
        timeout: Option<std::time::Duration>,
        buffer: &mut (impl AsMut<[u8]> + ?Sized),
    ) -> std::io::Result<(usize, u8)> {
        let mut n: usize = 0;
        let mut cur_index: u8 = 0;
        let slice = buffer.as_mut();
        let mut comp = false;
        let wait_for_logic = |datagram: &PartialDatagram| {
            let payload = datagram.payload_from(self.dg_pos.get());
            cur_index = datagram.index();
            n = std::cmp::min(slice.len(), payload.len());
            unsafe {
                slice.as_mut_ptr().copy_from(payload.as_ptr(), n);
            }
            comp = self.dg_pos.get() + n == datagram.len();
        };
        if self
            .set
            .wait_for(&self.index_in.get(), wait_for_logic, timeout)
        {
            if comp {
                self.dg_pos.set(0);
                let index_in = self.index_in.get() + 1;
                self.index_in.set(index_in);
            } else {
                let dg_pos = self.dg_pos.get() + n;
                self.dg_pos.set(dg_pos);
            }
            Ok((n, cur_index))
        } else {
            Err(std::io::ErrorKind::TimedOut.into())
        }
    }

    /// Inserts a new [`PartialDatagram`].
    pub(crate) fn insert(&self, dg: impl Into<PartialDatagram>) -> std::io::Result<()> {
        self.set.insert(dg.into())
    }

    /// Reads, without consuming, the next datagram in the queue.
    /// If the entire datagram is not available, it reads the bytes that are available.
    ///
    /// Returns a result. If peek was successful an Ok containing a tuple of the number of bytes peeked,
    /// the index of the datagram being peeked, and the datagram's size.
    pub(crate) fn peek(
        &self,
        buffer: &mut (impl AsMut<[u8]> + ?Sized),
    ) -> std::io::Result<(usize, u8, usize)> {
        let mut n: usize = 0;
        let mut cur_index: u8 = 0;
        let slice = buffer.as_mut();
        let mut dg_size: usize = 0;
        let wait_for_logic = |datagram: &PartialDatagram| {
            let payload = datagram.payload_from(0);
            cur_index = datagram.index();
            dg_size = datagram.len();
            n = std::cmp::min(slice.len(), payload.len());
            unsafe {
                slice.as_mut_ptr().copy_from(payload.as_ptr(), n);
            }
        };
        if self.set.wait_for(
            &self.index_in.get(),
            wait_for_logic,
            Some(std::time::Duration::from_secs(0)),
        ) {
            Ok((n, cur_index, dg_size))
        } else {
            Err(std::io::ErrorKind::WouldBlock.into())
        }
    }

    /// Returns the index of the next expected packet.
    pub(crate) fn index(&self) -> u8 {
        self.index_in.get()
    }
}

#[cfg(test)]
mod test {
    use super::DatagramStream;
    use super::PartialDatagram;
    use crate::experimental::turbo::support::ASet;
    use crate::experimental::turbo::support::BTreeSet;

    /// Tests [`DatagramStream::read`] method with an some available data.
    #[test]
    fn test_read_available() {
        let ds = DatagramStream::<ASet<PartialDatagram>>::new();
        let pd = crate::experimental::turbo::io::test::partial_datagram::create_pd(42, 1);
        let payload = std::vec::Vec::<u8>::from(pd.payload());
        ds.set.insert(pd).expect("failed to insert pd");

        let mut data = vec![0u8; payload.len()];
        let res = ds.read(None, &mut data).expect("ds failed to read");
        assert_eq!(res, (payload.len(), 1));
        assert_eq!(ds.index_in.get(), 2);
        assert_eq!(ds.dg_pos.get(), 0);
        assert_eq!(&payload[..], &data[..]);
    }

    /// Tests [`DatagramStream::read`] method with no available data.
    #[test]
    fn test_read_unavailable() {
        let ds = DatagramStream::<ASet<PartialDatagram>>::new();
        let pd = crate::experimental::turbo::io::test::partial_datagram::create_pd(42, 2);
        let payload = std::vec::Vec::<u8>::from(pd.payload());
        ds.set.insert(pd).expect("failed to insert pd");

        let mut data = vec![0u8; payload.len()];
        assert!(ds
            .read(Some(std::time::Duration::from_millis(100)), &mut data)
            .is_err());
    }

    /// Tests [`DatagramStream::read`] method with partial read.
    #[test]
    fn test_read_partial() {
        let ds = DatagramStream::<ASet<PartialDatagram>>::new();
        let pd = crate::experimental::turbo::io::test::partial_datagram::create_pd(42, 1);
        let payload = std::vec::Vec::<u8>::from(pd.payload());
        ds.set.insert(pd).expect("failed to insert pd");

        let mut data = vec![0u8; payload.len()];
        let res = ds
            .read(
                Some(std::time::Duration::from_millis(100)),
                &mut data[0..41],
            )
            .unwrap();
        assert_eq!(res, (41, 1));

        assert_eq!(ds.index_in.get(), 1);
        assert_eq!(ds.dg_pos.get(), 41);
        assert_eq!(&payload[..41], &data[..41]);

        let res = ds
            .read(
                Some(std::time::Duration::from_millis(100)),
                &mut data[0..41],
            )
            .expect("ds failed to read");
        assert_eq!(res, (1, 1));

        assert_eq!(ds.index_in.get(), 2);
        assert_eq!(ds.dg_pos.get(), 0);
        assert_eq!(&payload[41..], &data[..1]);
    }

    /// Tests [`DatagramStream::insert`] method.
    #[test]
    fn test_insert() {
        let ds = DatagramStream::<ASet<PartialDatagram>>::new();
        let pd = crate::experimental::turbo::io::test::partial_datagram::create_pd(42, 1);
        let payload = std::vec::Vec::<u8>::from(pd.payload());
        ds.insert(pd).expect("failed to insert pd");

        let mut data = vec![0u8; payload.len()];
        assert!(ds
            .read(Some(std::time::Duration::from_millis(100)), &mut data)
            .is_ok());
        assert_eq!(data.len(), payload.len());
        assert_eq!(&data[..], &payload[..]);
    }

    /// Tests [`DatagramStream::peek`] method.
    #[test]
    fn test_peek() {
        let ds = DatagramStream::<ASet<PartialDatagram>>::new();
        let pd = crate::experimental::turbo::io::test::partial_datagram::create_pd(42, 1);
        let payload = std::vec::Vec::<u8>::from(pd.payload());
        ds.insert(pd).expect("failed to insert pd");

        let mut data = vec![0u8; payload.len()];
        assert!(ds.peek(&mut data).is_ok());
        assert_eq!(data.len(), payload.len());
        assert_eq!(&data[..], &payload[..]);
        data = vec![0u8; payload.len()];

        assert!(ds
            .read(Some(std::time::Duration::from_millis(100)), &mut data)
            .is_ok());
        assert_eq!(data.len(), payload.len());
        assert_eq!(&data[..], &payload[..]);
    }
}
