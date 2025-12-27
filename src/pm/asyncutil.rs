use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::task::JoinHandle;

#[derive(Debug, Clone, Default)]
pub struct TaskTracker {
    active: Arc<AtomicUsize>,
    spawned_total: Arc<AtomicUsize>,
    active_blocking: Arc<AtomicUsize>,
    spawned_blocking_total: Arc<AtomicUsize>,
}

impl TaskTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Current number of tasks that are alive (running or pending).
    pub fn active_count(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }

    /// Total number of tasks ever spawned via this tracker.
    pub fn total_spawned(&self) -> usize {
        self.spawned_total.load(Ordering::SeqCst)
    }

    /// Current number of blocking tasks that are alive (running or pending on the blocking pool).
    pub fn active_blocking_count(&self) -> usize {
        self.active_blocking.load(Ordering::SeqCst)
    }

    /// Total number of blocking tasks ever spawned via this tracker.
    pub fn total_blocking_spawned(&self) -> usize {
        self.spawned_blocking_total.load(Ordering::SeqCst)
    }

    /// Spawn a Tokio task and track its lifetime using an RAII guard.
    ///
    /// When the task ends (normal completion, panic, or cancellation), the guard is dropped and
    /// `active_count()` is decremented.
    pub fn spawn<F, T>(&self, fut: F) -> JoinHandle<T>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        self.spawned_total.fetch_add(1, Ordering::SeqCst);
        self.active.fetch_add(1, Ordering::SeqCst);

        let guard = TaskGuard {
            counter: Arc::clone(&self.active),
        };

        tokio::spawn(async move {
            let _guard = guard;
            fut.await
        })
    }

    /// Spawn a Tokio *blocking* task and track its lifetime using an RAII guard.
    pub fn spawn_blocking<F, T>(&self, f: F) -> JoinHandle<T>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        self.spawned_blocking_total.fetch_add(1, Ordering::SeqCst);
        self.active_blocking.fetch_add(1, Ordering::SeqCst);

        let guard = TaskGuard {
            counter: Arc::clone(&self.active_blocking),
        };

        tokio::task::spawn_blocking(move || {
            let _guard = guard;
            f()
        })
    }
}

#[derive(Debug)]
pub struct TaskGuard {
    counter: Arc<AtomicUsize>,
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}


