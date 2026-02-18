use serde::Serialize;
use serde::ser::{SerializeSeq, Serializer};

#[derive(Clone, Debug)]
pub struct RingBuffer<const N: usize> {
    data: [u64; N],
    head: usize,
    count: usize,
}

impl<const N: usize> RingBuffer<N> {
    pub const fn new() -> Self {
        Self {
            data: [0; N],
            head: 0,
            count: 0,
        }
    }

    pub fn push(&mut self, value: u64) {
        self.data[self.head] = value;
        self.head = (self.head + 1) % N;
        if self.count < N {
            self.count += 1;
        }
    }

    pub fn sum(&self) -> u64 {
        if self.count == 0 {
            return 0;
        }
        if self.count < N {
            self.data[..self.count].iter().sum()
        } else {
            self.data.iter().sum()
        }
    }

    pub fn mean(&self) -> f64 {
        if self.count == 0 {
            return 0.0;
        }
        self.sum() as f64 / self.count as f64
    }

    pub fn latest(&self) -> Option<u64> {
        if self.count == 0 {
            return None;
        }
        let idx = if self.head == 0 { N - 1 } else { self.head - 1 };
        Some(self.data[idx])
    }

    /// Iterate from newest to oldest
    pub fn iter(&self) -> impl Iterator<Item = u64> + '_ {
        (0..self.count).map(move |i| {
            let idx = (self.head + N - 1 - i) % N;
            self.data[idx]
        })
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl<const N: usize> Default for RingBuffer<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Serialize for RingBuffer<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.count))?;
        for val in self.iter() {
            seq.serialize_element(&val)?;
        }
        seq.end()
    }
}

#[derive(Clone, Debug)]
pub struct AggregatedTimeSeries {
    l0: RingBuffer<10>,
    l1: RingBuffer<60>,
    l2: RingBuffer<60>,
    l0_push_count: u32,
    l1_push_count: u32,
}

impl AggregatedTimeSeries {
    pub fn new() -> Self {
        Self {
            l0: RingBuffer::new(),
            l1: RingBuffer::new(),
            l2: RingBuffer::new(),
            l0_push_count: 0,
            l1_push_count: 0,
        }
    }

    pub fn push_sample(&mut self, value: u64) {
        self.l0.push(value);
        self.l0_push_count += 1;

        if self.l0_push_count >= 10 {
            self.l1.push(self.l0.sum());
            self.l0_push_count = 0;
            self.l1_push_count += 1;

            if self.l1_push_count >= 60 {
                self.l2.push(self.l1.sum());
                self.l1_push_count = 0;
            }
        }
    }

    pub fn rate_per_sec(&self) -> f64 {
        if let Some(val) = self.l1.latest() {
            val as f64
        } else if self.l0.len() >= 2 {
            // L1 has no data yet (fewer than 10 poller cycles have run).
            // Compute the mean of L0 samples, excluding the oldest entry.
            // The oldest entry is dropped because for interface counters
            // the first delta equals the boot-time total (prev_total was 0),
            // producing a massive spike that would skew the average.
            // Using the mean (rather than latest) smooths out cycles where
            // traffic happens to be zero.
            let n = self.l0.len();
            let mut sum = self.l0.sum();
            // iter() goes newest→oldest; last() is the oldest entry
            if let Some(oldest) = self.l0.iter().last() {
                sum = sum.saturating_sub(oldest);
            }
            sum as f64 / (n - 1) as f64
        } else {
            0.0
        }
    }

    pub fn sparkline_data(&self) -> Vec<u64> {
        self.l2.iter().collect()
    }

    pub fn l0(&self) -> &RingBuffer<10> {
        &self.l0
    }

    pub fn l1(&self) -> &RingBuffer<60> {
        &self.l1
    }

    pub fn l2(&self) -> &RingBuffer<60> {
        &self.l2
    }
}

impl Default for AggregatedTimeSeries {
    fn default() -> Self {
        Self::new()
    }
}

impl Serialize for AggregatedTimeSeries {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Serialize as the L1 data (per-second buckets) for JSON output
        self.l1.serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== RingBuffer Tests (UT-4) ==========

    // UT-4.1: New buffer is empty
    #[test]
    fn test_ring_buffer_new_is_empty() {
        let buf = RingBuffer::<10>::new();
        assert_eq!(buf.len(), 0);
        assert!(buf.is_empty());
        assert_eq!(buf.sum(), 0);
    }

    // UT-4.2: Push 1 item
    #[test]
    fn test_ring_buffer_push_one() {
        let mut buf = RingBuffer::<10>::new();
        buf.push(42);
        assert_eq!(buf.len(), 1);
        assert_eq!(buf.latest(), Some(42));
        assert_eq!(buf.sum(), 42);
    }

    // UT-4.3: Push N items (N = capacity)
    #[test]
    fn test_ring_buffer_push_to_capacity() {
        let mut buf = RingBuffer::<5>::new();
        for i in 1..=5 {
            buf.push(i);
        }
        assert_eq!(buf.len(), 5);
        let items: Vec<u64> = buf.iter().collect();
        assert_eq!(items, vec![5, 4, 3, 2, 1]);
    }

    // UT-4.4: Push N+1 items (overflow)
    #[test]
    fn test_ring_buffer_overflow_one() {
        let mut buf = RingBuffer::<3>::new();
        for i in 1..=4 {
            buf.push(i);
        }
        assert_eq!(buf.len(), 3);
        let items: Vec<u64> = buf.iter().collect();
        // Oldest (1) is overwritten, newest 3 items remain
        assert_eq!(items, vec![4, 3, 2]);
    }

    // UT-4.5: Push N+5 items
    #[test]
    fn test_ring_buffer_overflow_five() {
        let mut buf = RingBuffer::<3>::new();
        for i in 1..=8 {
            buf.push(i);
        }
        assert_eq!(buf.len(), 3);
        let items: Vec<u64> = buf.iter().collect();
        assert_eq!(items, vec![8, 7, 6]);
    }

    // UT-4.6: Sum with 3 items
    #[test]
    fn test_ring_buffer_sum() {
        let mut buf = RingBuffer::<10>::new();
        buf.push(10);
        buf.push(20);
        buf.push(30);
        assert_eq!(buf.sum(), 60);
    }

    // UT-4.7: Mean with 3 items
    #[test]
    fn test_ring_buffer_mean() {
        let mut buf = RingBuffer::<10>::new();
        buf.push(10);
        buf.push(20);
        buf.push(30);
        assert_eq!(buf.mean(), 20.0);
    }

    // UT-4.8: Mean of empty buffer
    #[test]
    fn test_ring_buffer_mean_empty() {
        let buf = RingBuffer::<10>::new();
        assert_eq!(buf.mean(), 0.0);
    }

    // UT-4.9: Iter order
    #[test]
    fn test_ring_buffer_iter_order() {
        let mut buf = RingBuffer::<10>::new();
        buf.push(1);
        buf.push(2);
        buf.push(3);
        let items: Vec<u64> = buf.iter().collect();
        assert_eq!(items, vec![3, 2, 1]);
    }

    // UT-4.10: Iter after overflow
    #[test]
    fn test_ring_buffer_iter_after_overflow() {
        let mut buf = RingBuffer::<3>::new();
        buf.push(1);
        buf.push(2);
        buf.push(3);
        buf.push(4);
        let items: Vec<u64> = buf.iter().collect();
        assert_eq!(items, vec![4, 3, 2]);
    }

    // UT-4.11: Latest after overflow
    #[test]
    fn test_ring_buffer_latest_after_overflow() {
        let mut buf = RingBuffer::<3>::new();
        buf.push(1);
        buf.push(2);
        buf.push(3);
        buf.push(4);
        assert_eq!(buf.latest(), Some(4));
    }

    // ========== AggregatedTimeSeries Tests (UT-5) ==========

    // UT-5.1: Push 9 samples
    #[test]
    fn test_aggregated_push_9() {
        let mut ts = AggregatedTimeSeries::new();
        for _ in 0..9 {
            ts.push_sample(100);
        }
        assert_eq!(ts.l0().len(), 9);
        assert_eq!(ts.l1().len(), 0); // not yet aggregated
    }

    // UT-5.2: Push 10 samples
    #[test]
    fn test_aggregated_push_10() {
        let mut ts = AggregatedTimeSeries::new();
        for _ in 0..10 {
            ts.push_sample(100);
        }
        assert_eq!(ts.l0().len(), 10);
        assert_eq!(ts.l1().len(), 1);
    }

    // UT-5.3: Push 20 samples
    #[test]
    fn test_aggregated_push_20() {
        let mut ts = AggregatedTimeSeries::new();
        for _ in 0..20 {
            ts.push_sample(100);
        }
        assert_eq!(ts.l1().len(), 2);
    }

    // UT-5.4: Push 600 samples (60 * 10)
    #[test]
    fn test_aggregated_push_600() {
        let mut ts = AggregatedTimeSeries::new();
        for _ in 0..600 {
            ts.push_sample(100);
        }
        assert_eq!(ts.l1().len(), 60);
        assert_eq!(ts.l2().len(), 1);
    }

    // UT-5.5: rate_per_sec after 10 pushes
    #[test]
    fn test_aggregated_rate_per_sec() {
        let mut ts = AggregatedTimeSeries::new();
        for _ in 0..10 {
            ts.push_sample(100);
        }
        // L1 latest = sum of 10 * 100 = 1000
        assert_eq!(ts.rate_per_sec(), 1000.0);
    }

    // UT-5.5b: rate_per_sec with few samples (L0 fallback, mean excluding oldest)
    #[test]
    fn test_aggregated_rate_per_sec_few_samples() {
        let mut ts = AggregatedTimeSeries::new();
        ts.push_sample(100); // oldest — will be excluded
        ts.push_sample(200);
        ts.push_sample(150);
        // mean of [200, 150] = 175.0  (oldest 100 excluded)
        assert_eq!(ts.rate_per_sec(), 175.0);
    }

    // UT-5.5c: rate_per_sec with single sample returns 0
    #[test]
    fn test_aggregated_rate_per_sec_single_sample() {
        let mut ts = AggregatedTimeSeries::new();
        ts.push_sample(500);
        // Only 1 L0 sample, < 2 required
        assert_eq!(ts.rate_per_sec(), 0.0);
    }

    // UT-5.5d: rate_per_sec with no samples returns 0
    #[test]
    fn test_aggregated_rate_per_sec_empty() {
        let ts = AggregatedTimeSeries::new();
        assert_eq!(ts.rate_per_sec(), 0.0);
    }

    // UT-5.5e: rate_per_sec fallback drops interface boot-time spike
    #[test]
    fn test_aggregated_rate_per_sec_drops_spike() {
        let mut ts = AggregatedTimeSeries::new();
        ts.push_sample(2_000_000_000); // boot-time spike (oldest)
        ts.push_sample(10_000);
        ts.push_sample(12_000);
        ts.push_sample(8_000);
        ts.push_sample(11_000);
        // mean of [10000, 12000, 8000, 11000] = 10250.0
        assert_eq!(ts.rate_per_sec(), 10250.0);
    }

    // UT-5.5f: rate_per_sec with exactly 2 samples
    #[test]
    fn test_aggregated_rate_per_sec_two_samples() {
        let mut ts = AggregatedTimeSeries::new();
        ts.push_sample(9999); // oldest — excluded
        ts.push_sample(300);
        // mean of [300] = 300.0
        assert_eq!(ts.rate_per_sec(), 300.0);
    }

    // UT-5.6: sparkline_data
    #[test]
    fn test_aggregated_sparkline_data() {
        let mut ts = AggregatedTimeSeries::new();
        // Push 600 samples to get 1 L2 entry
        for _ in 0..600 {
            ts.push_sample(100);
        }
        let data = ts.sparkline_data();
        assert_eq!(data.len(), 1);
    }

    // UT-5.7: Push values [100; 10]
    #[test]
    fn test_aggregated_l1_sum() {
        let mut ts = AggregatedTimeSeries::new();
        for _ in 0..10 {
            ts.push_sample(100);
        }
        // L1 first entry = sum of 10 L0 entries = 10 * 100 = 1000
        assert_eq!(ts.l1().latest(), Some(1000));
    }
}
