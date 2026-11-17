//! The shim's link to its launcher (a fenders node's agent): an abstract Unix
//! socket `@fenders/run/<id>`. It has no filesystem entry, goes when the shim
//! exits, and binds once, so there is one shim per run. Only the launcher's
//! uid may connect (`SO_PEERCRED`).
//!
//! One request per connection, a line: `status`, `stop` or `collect`; the
//! answer is the run's status as one JSON line. `stop` ends the run (its VMM
//! is killed and its failed outcome posted). `collect`, once the run ended,
//! lets the shim exit after answering: until then it holds the run's end
//! report, across launcher restarts, for [`HOLD`] at most.
use serde_json::{Value, json};
use std::{
    os::unix::net::{SocketAddr, UnixListener},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Notify;

/// How long an ended run waits for its launcher to collect it.
pub const HOLD: Duration = Duration::from_secs(3600);

/// The abstract socket name of run `id`.
pub fn name(id: &str) -> String {
    format!("fenders/run/{id}")
}

/// Binds run `id`'s socket; fails if another shim holds the run.
pub fn bind(id: &str) -> std::io::Result<UnixListener> {
    use std::os::linux::net::SocketAddrExt;
    let address = SocketAddr::from_abstract_name(name(id).as_bytes())?;
    UnixListener::bind_addr(&address)
}

/// What the shim tells its launcher, and what the launcher asks of it.
pub struct Link {
    status: Mutex<Value>,
    pub stop: Notify,
    collected: Notify,
    launcher_uid: u32,
}

impl Link {
    pub fn new(status: Value, launcher_uid: u32) -> Arc<Self> {
        Arc::new(Self {
            status: Mutex::new(status),
            stop: Notify::new(),
            collected: Notify::new(),
            launcher_uid,
        })
    }

    /// Updates the status the launcher reads.
    pub fn update(&self, change: impl FnOnce(&mut serde_json::Map<String, Value>)) {
        let mut status = self.status.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(object) = status.as_object_mut() {
            change(object);
        }
    }

    pub fn status(&self) -> Value {
        self.status
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn ended(&self) -> bool {
        matches!(
            self.status()["state"].as_str(),
            Some("exited" | "failed" | "stopped")
        )
    }

    /// Waits until the launcher collected the ended run, or [`HOLD`].
    pub async fn collected(&self) {
        let _ = tokio::time::timeout(HOLD, self.collected.notified()).await;
    }

    async fn answer(self: &Arc<Self>, stream: tokio::net::UnixStream) -> std::io::Result<()> {
        let peer = stream.peer_cred()?;
        if peer.uid() != self.launcher_uid {
            return Ok(());
        }
        let (read, mut write) = stream.into_split();
        let mut line = String::new();
        let mut reader = BufReader::new(read.take(64));
        tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
            .await
            .map_err(|_| std::io::ErrorKind::TimedOut)??;
        let collect = match line.trim_end() {
            "status" => false,
            "stop" => {
                // Stored, so a stop asked before supervision waits is kept.
                self.stop.notify_one();
                false
            }
            "collect" => true,
            _ => {
                write
                    .write_all(b"{\"error\":\"unknown request\"}\n")
                    .await?;
                return Ok(());
            }
        };
        let mut answer = serde_json::to_vec(&self.status()).unwrap_or_default();
        answer.push(b'\n');
        write.write_all(&answer).await?;
        write.flush().await?;
        if collect && self.ended() {
            self.collected.notify_one();
        }
        Ok(())
    }
}

/// Serves the launcher on `listener` for the shim's life.
pub async fn serve(listener: UnixListener, link: Arc<Link>) {
    if listener.set_nonblocking(true).is_err() {
        return;
    }
    let Ok(listener) = tokio::net::UnixListener::from_std(listener) else {
        return;
    };
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let link = link.clone();
        tokio::spawn(async move {
            let _ = link.answer(stream).await;
        });
    }
}

/// A run's status before it starts.
pub fn initial(
    id: &str,
    key: &str,
    component: &str,
    uid: Option<u32>,
    cpu: Option<usize>,
    guest: &Value,
) -> Value {
    json!({"id": id, "key": key, "state": "starting", "component": component,
        "uid": uid, "cpu": cpu, "pid": std::process::id(),
        "cpu_percent": guest["cpu_percent"], "host_memory_mib": guest["host_memory_mib"],
        "created": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64()).unwrap_or(0.0)})
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    async fn ask(id: &str, request: &str) -> Value {
        use std::os::linux::net::SocketAddrExt;
        let address = SocketAddr::from_abstract_name(name(id).as_bytes()).unwrap();
        let stream = std::os::unix::net::UnixStream::connect_addr(&address).unwrap();
        stream.set_nonblocking(true).unwrap();
        let mut stream = tokio::net::UnixStream::from_std(stream).unwrap();
        stream
            .write_all(format!("{request}\n").as_bytes())
            .await
            .unwrap();
        let mut answer = String::new();
        stream.read_to_string(&mut answer).await.unwrap();
        serde_json::from_str(&answer).unwrap()
    }

    #[tokio::test]
    async fn one_shim_per_run_answers_its_launcher_and_waits_to_be_collected() {
        let id = format!("test-{}", std::process::id());
        let listener = bind(&id).unwrap();
        assert!(bind(&id).is_err(), "a run's name binds once");
        let uid = unsafe { libc::getuid() };
        let link = Link::new(
            initial(&id, "key-1", "/c.cwasm", None, Some(3), &json!({})),
            uid,
        );
        tokio::spawn(serve(listener, link.clone()));
        assert_eq!(ask(&id, "status").await["state"], "starting");
        link.update(|s| {
            s.insert("state".into(), json!("running"));
        });
        assert_eq!(ask(&id, "stop").await["state"], "running");
        tokio::time::timeout(Duration::from_secs(1), link.stop.notified())
            .await
            .expect("stop reaches the supervisor");
        // Not collected while running.
        assert_eq!(ask(&id, "collect").await["state"], "running");
        let collected = tokio::spawn({
            let link = link.clone();
            async move { link.collected().await }
        });
        link.update(|s| {
            s.insert("state".into(), json!("exited"));
        });
        assert_eq!(ask(&id, "collect").await["state"], "exited");
        tokio::time::timeout(Duration::from_secs(1), collected)
            .await
            .expect("collected")
            .unwrap();
        assert!(ask(&id, "bogus").await["error"].is_string());
    }
}
