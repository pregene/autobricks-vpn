use super::queue::Queue;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

/// A single worker thread that sleeps on its queue's condition variable.
pub struct QueueWorker<T> {
    queue: Arc<Queue<T>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
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
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::queue::Queue;
    use super::QueueWorker;
    use std::sync::{mpsc, Arc};
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
}
