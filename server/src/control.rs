use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

#[derive(Clone, Default)]
pub struct AgentRegistry {
    inner: Arc<RwLock<HashMap<String, AgentSession>>>,
}

#[derive(Clone)]
struct AgentSession {
    id: u64,
    tx: mpsc::Sender<Arc<str>>,
}

pub struct Registration {
    pub id: u64,
    pub rx: mpsc::Receiver<Arc<str>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteStatus {
    Queued,
    NotConnected,
    QueueFull,
}

impl AgentRegistry {
    pub async fn register(&self, fingerprint: String, id: u64, queue: usize) -> Registration {
        let (tx, rx) = mpsc::channel(queue);
        self.inner.write().await.insert(fingerprint, AgentSession { id, tx });
        Registration { id, rx }
    }

    pub async fn unregister(&self, fingerprint: &str, id: u64) {
        let mut guard = self.inner.write().await;
        if guard.get(fingerprint).is_some_and(|session| session.id == id) {
            guard.remove(fingerprint);
        }
    }

    pub async fn active_count(&self) -> usize {
        self.inner.read().await.len()
    }

    pub async fn route(&self, target: &str, command: Arc<str>, max_broadcast: usize) -> (usize, usize, RouteStatus) {
        let mut stale = Vec::<(String, u64)>::new();
        let result = {
            let guard = self.inner.read().await;
            if target.eq_ignore_ascii_case("broadcast") {
                let attempted = guard.len().min(max_broadcast);
                if attempted == 0 {
                    return (0, 0, RouteStatus::NotConnected);
                }
                let mut queued = 0usize;
                let mut dropped = 0usize;
                let mut closed = 0usize;
                for (fingerprint, session) in guard.iter().take(max_broadcast) {
                    match session.tx.try_send(Arc::clone(&command)) {
                        Ok(()) => queued += 1,
                        Err(mpsc::error::TrySendError::Full(_)) => dropped += 1,
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            dropped += 1;
                            closed += 1;
                            stale.push((fingerprint.clone(), session.id));
                        }
                    }
                }
                dropped += guard.len().saturating_sub(max_broadcast);
                let status = if queued == attempted && dropped == 0 {
                    RouteStatus::Queued
                } else if queued == 0 && closed == attempted && guard.len() <= max_broadcast {
                    RouteStatus::NotConnected
                } else {
                    RouteStatus::QueueFull
                };
                (queued, dropped, status)
            } else {
                let target_lower = target.to_ascii_lowercase();
                if let Some(session) = guard.get(&target_lower) {
                    match session.tx.try_send(Arc::clone(&command)) {
                        Ok(()) => (1, 0, RouteStatus::Queued),
                        Err(mpsc::error::TrySendError::Full(_)) => (0, 1, RouteStatus::QueueFull),
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            stale.push((target_lower, session.id));
                            (0, 1, RouteStatus::NotConnected)
                        }
                    }
                } else if let Some((fingerprint, session)) = guard.iter().find(|(fingerprint, _)| fingerprint.eq_ignore_ascii_case(target)) {
                    match session.tx.try_send(Arc::clone(&command)) {
                        Ok(()) => (1, 0, RouteStatus::Queued),
                        Err(mpsc::error::TrySendError::Full(_)) => (0, 1, RouteStatus::QueueFull),
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            stale.push((fingerprint.clone(), session.id));
                            (0, 1, RouteStatus::NotConnected)
                        }
                    }
                } else {
                    return (0, 0, RouteStatus::NotConnected);
                }
            }
        };

        if !stale.is_empty() {
            let mut guard = self.inner.write().await;
            for (fingerprint, id) in stale {
                if guard.get(&fingerprint).is_some_and(|session| session.id == id) {
                    guard.remove(&fingerprint);
                }
            }
        }
        result
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn routes_unicast_and_broadcast_with_bounds() {
        let registry = AgentRegistry::default();
        let fp1 = "a".repeat(64);
        let fp2 = "b".repeat(64);
        let mut one = registry.register(fp1.clone(), 1, 2).await.rx;
        let mut two = registry.register(fp2.clone(), 2, 2).await.rx;

        let (queued, dropped, status) = registry.route(&fp1, Arc::<str>::from("CMD:RECONNECT"), 10).await;
        assert_eq!((queued, dropped, status), (1, 0, RouteStatus::Queued));
        let (queued, dropped, status) = registry.route(&fp1, Arc::<str>::from("CMD:CLOSE"), 10).await;
        assert_eq!((queued, dropped, status), (1, 0, RouteStatus::Queued));

        let (queued, dropped, status) = registry.route("broadcast", Arc::<str>::from("REQ:DATA"), 2).await;
        assert_eq!((queued, dropped, status), (1, 1, RouteStatus::QueueFull));
        assert_eq!(one.recv().await.as_deref(), Some("CMD:RECONNECT"));
        assert_eq!(one.recv().await.as_deref(), Some("CMD:CLOSE"));
        assert_eq!(two.recv().await.as_deref(), Some("REQ:DATA"));
    }
    #[tokio::test]
    async fn broadcast_reports_queue_full_when_all_connected_queues_are_full() {
        let registry = AgentRegistry::default();
        let fp = "c".repeat(64);
        let mut rx = registry.register(fp.clone(), 3, 1).await.rx;
        assert_eq!(registry.route(&fp, Arc::<str>::from("CMD:CLOSE"), 10).await.2, RouteStatus::Queued);
        let result = registry.route("broadcast", Arc::<str>::from("REQ:DATA"), 10).await;
        assert_eq!(result.2, RouteStatus::QueueFull);
        assert_eq!(result.1, 1);
        assert_eq!(rx.recv().await.as_deref(), Some("CMD:CLOSE"));
    }

    #[tokio::test]
    async fn closed_registration_is_reported_offline_not_queue_full() {
        let registry = AgentRegistry::default();
        let fp = "d".repeat(64);
        let registration = registry.register(fp.clone(), 4, 1).await;
        drop(registration.rx);
        let result = registry.route(&fp, Arc::<str>::from("CMD:CLOSE"), 10).await;
        assert_eq!(result, (0, 1, RouteStatus::NotConnected));
    }

    #[tokio::test]
    async fn stale_session_cannot_remove_newer_registration() {
        let registry = AgentRegistry::default();
        let fp = "e".repeat(64);
        let old = registry.register(fp.clone(), 10, 1).await;
        let new = registry.register(fp.clone(), 11, 1).await;
        drop(old.rx);
        registry.unregister(&fp, 10).await;
        let result = registry.route(&fp, Arc::<str>::from("CMD:RECONNECT"), 10).await;
        assert_eq!(result, (1, 0, RouteStatus::Queued));
        drop(new.rx);
    }

    #[tokio::test]
    async fn closed_session_is_pruned_from_registry() {
        let registry = AgentRegistry::default();
        let fp = "f".repeat(64);
        let registration = registry.register(fp.clone(), 12, 1).await;
        drop(registration.rx);
        assert_eq!(registry.route(&fp, Arc::<str>::from("CMD:CLOSE"), 10).await, (0, 1, RouteStatus::NotConnected));
        assert_eq!(registry.active_count().await, 0);
    }

    #[tokio::test]
    async fn case_insensitive_fingerprint_target_routes_without_copying_command() {
        let registry = AgentRegistry::default();
        let fp = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let mut rx = registry.register(fp.to_owned(), 13, 1).await.rx;
        let upper = fp.to_ascii_uppercase();
        assert_eq!(registry.route(&upper, Arc::<str>::from("CMD:RECONNECT"), 10).await, (1, 0, RouteStatus::Queued));
        assert_eq!(rx.recv().await.as_deref(), Some("CMD:RECONNECT"));
    }

}
