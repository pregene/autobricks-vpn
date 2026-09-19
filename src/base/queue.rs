use std::collections::VecDeque;
use std::fmt;
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::Duration;

/// A bounded FIFO queue for passing ownership between producer and worker threads.
///
/// The backing storage is allocated once when the queue is created. `push` wakes a
/// waiting consumer immediately; the capacity is a bound, not a batching threshold.
pub struct Queue<T> {
    capacity: usize,
    state: Mutex<State<T>>,
    not_empty: Condvar,
}

/// A non-blocking reservation of the queue's oldest item.
///
/// `pop` commits removal. Dropping the reservation without calling `pop`
/// restores the item at the front, so a consumer can retry after `WouldBlock`.
pub struct QueueFront<'a, T> {
    queue: &'a Queue<T>,
    item: Option<T>,
}

impl<T> QueueFront<'_, T> {
    pub fn value(&self) -> &T {
        self.item
            .as_ref()
            .expect("queue front reservation is valid")
    }

    pub fn pop(mut self) -> T {
        self.item.take().expect("queue front reservation is valid")
    }
}

impl<T> Drop for QueueFront<'_, T> {
    fn drop(&mut self) {
        let Some(item) = self.item.take() else {
            return;
        };
        let mut state = self.queue.lock_state();
        if state.closed {
            return;
        }
        if state.items.len() == self.queue.capacity {
            state.items.pop_back();
        }
        state.items.push_front(item);
        drop(state);
        self.queue.not_empty.notify_one();
    }
}

struct State<T> {
    items: VecDeque<T>,
    closed: bool,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidCapacity;

impl fmt::Display for InvalidCapacity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("queue capacity must be greater than zero")
    }
}

impl std::error::Error for InvalidCapacity {}

#[derive(Debug, Eq, PartialEq)]
pub struct PushError<T>(pub T);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TryPopError {
    Empty,
    Closed,
}

impl<T> Queue<T> {
    pub fn new(capacity: usize) -> Result<Self, InvalidCapacity> {
        if capacity == 0 {
            return Err(InvalidCapacity);
        }
        Ok(Self {
            capacity,
            state: Mutex::new(State {
                items: VecDeque::with_capacity(capacity),
                closed: false,
                generation: 0,
            }),
            not_empty: Condvar::new(),
        })
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn len(&self) -> usize {
        self.lock_state().items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn is_closed(&self) -> bool {
        self.lock_state().closed
    }

    /// Generation used to wait for a new push or another external progress event.
    pub fn generation(&self) -> u64 {
        self.lock_state().generation
    }

    pub fn notify_change(&self) {
        let mut state = self.lock_state();
        state.generation = state.generation.wrapping_add(1);
        drop(state);
        self.not_empty.notify_all();
    }

    pub fn wait_for_change(&self, observed: u64) -> bool {
        let mut state = self.lock_state();
        while state.generation == observed && !state.closed {
            state = self
                .not_empty
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        !state.closed
    }

    /// Enqueue an item without blocking the network producer.
    ///
    /// If the queue is full, the oldest item is removed before the new item is
    /// inserted. The removed item is returned for drop accounting or buffer reuse.
    pub fn push(&self, item: T) -> Result<Option<T>, PushError<T>> {
        let mut state = self.lock_state();
        if state.closed {
            return Err(PushError(item));
        }
        let dropped = if state.items.len() == self.capacity {
            state.items.pop_front()
        } else {
            None
        };
        state.items.push_back(item);
        state.generation = state.generation.wrapping_add(1);
        drop(state);
        self.not_empty.notify_one();
        Ok(dropped)
    }

    /// Dequeue an item, waiting while the queue is empty and open.
    ///
    /// Closing the queue discards pending items and makes this return `None`.
    pub fn pop(&self) -> Option<T> {
        let mut state = self.lock_state();
        while state.items.is_empty() && !state.closed {
            state = self
                .not_empty
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        if state.closed {
            return None;
        }
        state.items.pop_front()
    }

    /// Reserve the oldest item without committing its removal.
    ///
    /// Producers are not blocked while the returned reservation is processed.
    /// Call `QueueFront::pop` only after the operation succeeds. Dropping the
    /// reservation restores the item at the front for retry.
    pub fn peek(&self) -> Option<QueueFront<'_, T>> {
        let mut state = self.lock_state();
        while state.items.is_empty() && !state.closed {
            state = self
                .not_empty
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        if state.closed {
            return None;
        }
        let item = state.items.pop_front();
        drop(state);
        item.map(|item| QueueFront {
            queue: self,
            item: Some(item),
        })
    }

    pub fn try_peek(&self) -> Result<QueueFront<'_, T>, TryPopError> {
        let mut state = self.lock_state();
        if let Some(item) = state.items.pop_front() {
            return Ok(QueueFront {
                queue: self,
                item: Some(item),
            });
        }
        if state.closed {
            Err(TryPopError::Closed)
        } else {
            Err(TryPopError::Empty)
        }
    }

    /// Dequeue an item, waiting up to `timeout` while the queue is empty.
    pub fn pop_timeout(&self, timeout: Duration) -> Option<T> {
        let mut state = self.lock_state();
        if state.items.is_empty() && !state.closed {
            let (next_state, _) = self
                .not_empty
                .wait_timeout(state, timeout)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state = next_state;
        }
        if state.closed {
            return None;
        }
        state.items.pop_front()
    }

    /// Dequeue an item without waiting.
    pub fn try_pop(&self) -> Result<T, TryPopError> {
        let mut state = self.lock_state();
        if let Some(item) = state.items.pop_front() {
            return Ok(item);
        }
        if state.closed {
            Err(TryPopError::Closed)
        } else {
            Err(TryPopError::Empty)
        }
    }

    /// Stop accepting and consuming items, then wake every blocked consumer.
    pub fn close(&self) {
        let mut state = self.lock_state();
        if state.closed {
            return;
        }
        state.closed = true;
        state.items.clear();
        state.generation = state.generation.wrapping_add(1);
        drop(state);
        self.not_empty.notify_all();
    }

    fn lock_state(&self) -> MutexGuard<'_, State<T>> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::{PushError, Queue, TryPopError};
    use std::sync::{mpsc, Arc};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn rejects_zero_capacity() {
        assert!(Queue::<u8>::new(0).is_err());
    }

    #[test]
    fn preserves_fifo_order_and_capacity() {
        let queue = Queue::new(2).unwrap();
        assert_eq!(queue.capacity(), 2);
        assert_eq!(queue.push(10), Ok(None));
        assert_eq!(queue.push(20), Ok(None));
        assert_eq!(queue.len(), 2);
        assert_eq!(queue.push(30), Ok(Some(10)));
        assert_eq!(queue.try_pop(), Ok(20));
        assert_eq!(queue.try_pop(), Ok(30));
        assert_eq!(queue.try_pop(), Err(TryPopError::Empty));
        assert!(queue.is_empty());
    }

    #[test]
    fn push_wakes_waiting_consumer_immediately() {
        let queue = Arc::new(Queue::new(64).unwrap());
        let worker_queue = Arc::clone(&queue);
        let (sender, receiver) = mpsc::channel();
        let worker = thread::spawn(move || sender.send(worker_queue.pop()).unwrap());

        thread::sleep(Duration::from_millis(10));
        assert_eq!(queue.push(7), Ok(None));

        assert_eq!(
            receiver.recv_timeout(Duration::from_secs(1)).unwrap(),
            Some(7)
        );
        worker.join().unwrap();
    }

    #[test]
    fn close_wakes_consumer_and_discards_existing_items() {
        let queue = Arc::new(Queue::new(2).unwrap());
        assert_eq!(queue.push(1), Ok(None));
        queue.close();

        assert!(queue.is_closed());
        assert_eq!(queue.pop(), None);
        assert_eq!(queue.try_pop(), Err(TryPopError::Closed));
        assert_eq!(queue.push(2), Err(PushError(2)));
    }

    #[test]
    fn full_queue_drops_oldest_without_blocking_producer() {
        let queue = Queue::new(1).unwrap();
        assert_eq!(queue.push(1), Ok(None));
        assert_eq!(queue.push(2), Ok(Some(1)));
        assert_eq!(queue.pop(), Some(2));
    }

    #[test]
    fn timed_pop_returns_when_no_item_arrives() {
        let queue = Queue::<u8>::new(1).unwrap();
        assert_eq!(queue.pop_timeout(Duration::from_millis(1)), None);
        assert!(!queue.is_closed());
    }

    #[test]
    fn peek_restores_front_until_pop_commits_removal() {
        let queue = Queue::new(2).unwrap();
        queue.push(10).unwrap();
        queue.push(20).unwrap();
        {
            let front = queue.peek().unwrap();
            assert_eq!(*front.value(), 10);
        }
        let front = queue.peek().unwrap();
        assert_eq!(front.pop(), 10);
        assert_eq!(queue.pop(), Some(20));
    }
}
