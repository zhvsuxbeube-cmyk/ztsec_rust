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
    tx: mpsc::Sender<String>,
}

pub struct Registration {
    pub id: u64,
    pub rx: mpsc::Receiver<String>,
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

    pub async fn route(&self, target: &str, command: &str, max_broadcast: usize) -> (usize, usize, RouteStatus) {
        let guard = self.inner.read().await;
        if target.eq_ignore_ascii_case("broadcast") {
            let mut queued = 0usize;
            let mut dropped = 0usize;
            for session in guard.values().take(max_broadcast) {
                match session.tx.try_send(command.to_owned()) {
                    Ok(()) => queued += 1,
                    Err(_) => dropped += 1,
                }
            }
            if guard.len() > max_broadcast {
                dropped += guard.len() - max_broadcast;
            }
            return if queued > 0 && dropped == 0 {
                (queued, dropped, RouteStatus::Queued)
            } else if queued > 0 {
                (queued, dropped, RouteStatus::QueueFull)
            } else {
                (queued, dropped, RouteStatus::NotConnected)
            };
        }

        let Some(session) = guard.get(&target.to_ascii_lowercase()) else {
            // Fingerprints are stored lowercase, but tolerate callers that supply uppercase.
            let Some((_, session)) = guard.iter().find(|(fingerprint, _)| fingerprint.eq_ignore_ascii_case(target)) else {
                return (0, 0, RouteStatus::NotConnected);
            };
            return match session.tx.try_send(command.to_owned()) {
                Ok(()) => (1, 0, RouteStatus::Queued),
                Err(_) => (0, 1, RouteStatus::QueueFull),
            };
        };
        match session.tx.try_send(command.to_owned()) {
            Ok(()) => (1, 0, RouteStatus::Queued),
            Err(_) => (0, 1, RouteStatus::QueueFull),
        }
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

        let (queued, dropped, status) = registry.route(&fp1, "CMD:RECONNECT", 10).await;
        assert_eq!((queued, dropped, status), (1, 0, RouteStatus::Queued));
        let (queued, dropped, status) = registry.route(&fp1, "CMD:CLOSE", 10).await;
        assert_eq!((queued, dropped, status), (1, 0, RouteStatus::Queued));

        let (queued, dropped, status) = registry.route("broadcast", "REQ:DATA", 2).await;
        assert_eq!((queued, dropped, status), (1, 1, RouteStatus::QueueFull));
        assert_eq!(one.recv().await.as_deref(), Some("CMD:RECONNECT"));
        assert_eq!(one.recv().await.as_deref(), Some("CMD:CLOSE"));
        assert_eq!(two.recv().await.as_deref(), Some("REQ:DATA"));
    }
}
