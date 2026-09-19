use super::queue::Queue;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// A single worker thread that sleeps on its queue's condition variable.
pub struct QueueWorker<T> {
    queue: Arc<Queue<T>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    retry_signal: Option<Arc<WorkerSignal>>,
}

/// Event used to resume a worker after an external I/O state change.
pub struct WorkerSignal {
    generation: Mutex<u64>,
    changed: Condvar,
}

impl Default for WorkerSignal {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkerSignal {
    pub fn new() -> Self {
        Self {
            generation: Mutex::new(0),
            changed: Condvar::new(),
        }
    }

    pub fn generation(&self) -> u64 {
        *self
            .generation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn notify(&self) {
        let mut generation = self
            .generation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *generation = generation.wrapping_add(1);
        drop(generation);
        self.changed.notify_all();
    }

    pub fn wait(&self, observed: u64) {
        let generation = self
            .generation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        drop(
            self.changed
                .wait_while(generation, |generation| *generation == observed)
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
    }

    fn wait_for_change(&self, observed: u64, timeout: Duration) -> bool {
        let generation = self
            .generation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if *generation != observed {
            return true;
        }
        let (generation, result) = self
            .changed
            .wait_timeout_while(generation, timeout, |generation| *generation == observed)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        !result.timed_out() || *generation != observed
    }
}

impl<T: Send + 'static> QueueWorker<T> {
    /// Create a worker for an existing queue instance.
    pub fn spawn(
        name: impl Into<String>,
        queue: Arc<Queue<T>>,
        mut process: impl FnMut(T) + Send + 'static,
    ) -> io::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let worker_queue = Arc::clone(&queue);
        let worker_stop = Arc::clone(&stop);
        let handle = thread::Builder::new()
            .name(name.into())
            .spawn(move || loop {
                // Check before entering the condition-variable wait.
                if worker_stop.load(Ordering::Acquire) {
                    break;
                }

                let item = worker_queue.pop();

                // A wake-up may be a stop request. Always check the bit first.
                if worker_stop.load(Ordering::Acquire) {
                    break;
                }

                let Some(item) = item else {
                    break;
                };
                process(item);
            })?;

        Ok(Self {
            queue,
            stop,
            handle: Some(handle),
            retry_signal: None,
        })
    }

    /// Spawn a worker that removes the front item only when `process` succeeds.
    /// A `false` result restores the item at the front and retries it later.
    pub fn spawn_peek(
        name: impl Into<String>,
        queue: Arc<Queue<T>>,
        retry_signal: Arc<WorkerSignal>,
        retry_timeout: Duration,
        mut process: impl FnMut(&T) -> bool + Send + 'static,
    ) -> io::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let worker_queue = Arc::clone(&queue);
        let worker_stop = Arc::clone(&stop);
        let worker_signal = Arc::clone(&retry_signal);
        let handle = thread::Builder::new().name(name.into()).spawn(move || {
            let mut retry_started = None;
            loop {
                if worker_stop.load(Ordering::Acquire) {
                    break;
                }
                let Some(front) = worker_queue.peek() else {
                    break;
                };
                if worker_stop.load(Ordering::Acquire) {
                    break;
                }
                let observed = worker_signal.generation();
                if process(front.value()) {
                    front.pop();
                    retry_started = None;
                } else {
                    let started = retry_started.get_or_insert_with(Instant::now);
                    let elapsed = started.elapsed();
                    if elapsed >= retry_timeout {
                        front.pop();
                        retry_started = None;
                    } else {
                        drop(front);
                        worker_signal
                            .wait_for_change(observed, retry_timeout.saturating_sub(elapsed));
                    }
                }
            }
        })?;

        Ok(Self {
            queue,
            stop,
            handle: Some(handle),
            retry_signal: Some(retry_signal),
        })
    }

    /// Keep revisiting an unconsumed front item; wait only when the queue is empty.
    pub fn spawn_scan_peek(
        name: impl Into<String>,
        queue: Arc<Queue<T>>,
        mut process: impl FnMut(&T) -> bool + Send + 'static,
    ) -> io::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let worker_queue = Arc::clone(&queue);
        let worker_stop = Arc::clone(&stop);
        let handle = thread::Builder::new()
            .name(name.into())
            .spawn(move || loop {
                if worker_stop.load(Ordering::Acquire) {
                    break;
                }
                let Some(front) = worker_queue.peek() else {
                    break;
                };
                if worker_stop.load(Ordering::Acquire) {
                    break;
                }
                if process(front.value()) {
                    front.pop();
                } else {
                    drop(front);
                    thread::yield_now();
                }
            })?;
        Ok(Self {
            queue,
            stop,
            handle: Some(handle),
            retry_signal: None,
        })
    }

    pub fn queue(&self) -> &Arc<Queue<T>> {
        &self.queue
    }

    pub fn is_stop_requested(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }

    /// Set the stop bit before waking the thread from its condition-variable wait.
    pub fn request_stop(&self) {
        self.stop.store(true, Ordering::Release);
        self.queue.close();
        if let Some(signal) = &self.retry_signal {
            signal.notify();
        }
    }

    pub fn join(&mut self) -> thread::Result<()> {
        if let Some(handle) = self.handle.take() {
            handle.join()
        } else {
            Ok(())
        }
    }

    pub fn stop(&mut self) -> thread::Result<()> {
        self.request_stop();
        self.join()
    }
}

impl<T> Drop for QueueWorker<T> {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.queue.close();
        if let Some(signal) = &self.retry_signal {
            signal.notify();
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::queue::Queue;
    use super::{QueueWorker, WorkerSignal};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Arc,
    };
    use std::time::Duration;

    #[test]
    fn processes_items_from_supplied_queue() {
        let queue = Arc::new(Queue::new(8).unwrap());
        let (sender, receiver) = mpsc::channel();
        let mut worker = QueueWorker::spawn("queue-test", Arc::clone(&queue), move |item| {
            sender.send(item).unwrap();
        })
        .unwrap();

        assert_eq!(queue.push(42), Ok(None));
        assert_eq!(receiver.recv_timeout(Duration::from_secs(1)).unwrap(), 42);
        worker.stop().unwrap();
        assert!(worker.is_stop_requested());
    }

    #[test]
    fn stop_wakes_idle_worker() {
        let queue = Arc::new(Queue::<u8>::new(8).unwrap());
        let mut worker = QueueWorker::spawn("idle-queue-test", queue, |_| {}).unwrap();
        worker.stop().unwrap();
        assert!(worker.is_stop_requested());
    }

    #[test]
    fn peek_retry_timeout_discards_blocked_front() {
        let queue = Arc::new(Queue::new(8).unwrap());
        let (sender, receiver) = mpsc::channel();
        let started = std::time::Instant::now();
        let mut worker = QueueWorker::spawn_peek(
            "peek-timeout-test",
            Arc::clone(&queue),
            Arc::new(WorkerSignal::new()),
            Duration::from_millis(20),
            move |item| {
                if *item == 2 {
                    sender.send(started.elapsed()).unwrap();
                    true
                } else {
                    false
                }
            },
        )
        .unwrap();

        assert_eq!(queue.push(1), Ok(None));
        assert_eq!(queue.push(2), Ok(None));
        let elapsed = receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(elapsed >= Duration::from_millis(20));
        worker.stop().unwrap();
    }

    #[test]
    fn scan_peek_retries_front_without_new_push_or_timeout_drop() {
        let queue = Arc::new(Queue::new(8).unwrap());
        let attempts = Arc::new(AtomicUsize::new(0));
        let (sender, receiver) = mpsc::channel();
        let attempts_worker = Arc::clone(&attempts);
        let mut worker =
            QueueWorker::spawn_scan_peek("scan-peek-test", Arc::clone(&queue), move |item| {
                let count = attempts_worker.fetch_add(1, Ordering::Relaxed) + 1;
                if count < 3 {
                    return false;
                }
                sender.send(*item).unwrap();
                true
            })
            .unwrap();
        queue.push(42).unwrap();
        assert_eq!(receiver.recv_timeout(Duration::from_secs(1)).unwrap(), 42);
        assert!(attempts.load(Ordering::Relaxed) >= 3);
        worker.stop().unwrap();
    }
}
