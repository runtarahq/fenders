//! Bounded, process-local observations and ownership of daemon background loops.
//! Successful iterations are not proof of leadership, placement or guest health.
use crate::{
    error::{Error, Result},
    model::uid,
};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    future::Future,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    task::{Id, JoinSet},
    time::Instant,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Component {
    Scheduler,
    PickupListener,
    InvitationEmail,
}
impl Component {
    fn name(self) -> &'static str {
        match self {
            Self::Scheduler => "scheduler",
            Self::PickupListener => "pickup_listener",
            Self::InvitationEmail => "invitation_email",
        }
    }
}
struct Observation {
    state: &'static str,
    started: Option<Instant>,
    completed: Option<Instant>,
    succeeded: Option<Instant>,
    duration_ms: Option<u64>,
    iterations: u64,
    failures: u64,
    consecutive_failures: u64,
    termination: Option<&'static str>,
}
pub struct Monitor {
    process: String,
    started: Instant,
    observations: Mutex<BTreeMap<Component, Observation>>,
}
impl Default for Monitor {
    fn default() -> Self {
        Self {
            process: uid(),
            started: Instant::now(),
            observations: Mutex::new(BTreeMap::new()),
        }
    }
}
fn millis(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}
impl Monitor {
    fn register(&self, component: Component) -> Result<()> {
        let mut observations = self.observations.lock().map_err(|_| Error::internal())?;
        if observations.contains_key(&component) {
            return Err(Error::invalid("background component already registered"));
        }
        observations.insert(
            component,
            Observation {
                state: "waiting",
                started: None,
                completed: None,
                succeeded: None,
                duration_ms: None,
                iterations: 0,
                failures: 0,
                consecutive_failures: 0,
                termination: None,
            },
        );
        Ok(())
    }
    fn begin(&self, component: Component) {
        let mut observations = self
            .observations
            .lock()
            .expect("background monitor poisoned");
        let observation = observations
            .get_mut(&component)
            .expect("registered background component");
        observation.state = "running";
        observation.started = Some(Instant::now());
    }
    fn finish(&self, component: Component, success: bool) {
        let now = Instant::now();
        let mut observations = self
            .observations
            .lock()
            .expect("background monitor poisoned");
        let observation = observations
            .get_mut(&component)
            .expect("registered background component");
        observation.state = "waiting";
        observation.duration_ms = observation
            .started
            .map(|at| millis(now.saturating_duration_since(at)));
        observation.completed = Some(now);
        observation.iterations = observation.iterations.saturating_add(1);
        if success {
            observation.succeeded = Some(now);
            observation.consecutive_failures = 0;
        } else {
            observation.failures = observation.failures.saturating_add(1);
            observation.consecutive_failures = observation.consecutive_failures.saturating_add(1);
        }
    }
    fn terminated(&self, component: Component, reason: &'static str) {
        let mut observations = self
            .observations
            .lock()
            .expect("background monitor poisoned");
        let observation = observations
            .get_mut(&component)
            .expect("registered background component");
        observation.state = "terminated";
        observation.termination = Some(reason);
    }
    pub fn snapshot(&self) -> Result<Value> {
        let now = Instant::now();
        let observations = self.observations.lock().map_err(|_| Error::internal())?;
        let age = |at: Option<Instant>| at.map(|at| millis(now.saturating_duration_since(at)));
        let components: Vec<_> = observations
            .iter()
            .map(|(component, observation)| {
                json!({
                    "component":component,"state":observation.state,
                    "last_started_age_ms":age(observation.started),
                    "last_completed_age_ms":age(observation.completed),
                    "last_success_age_ms":age(observation.succeeded),
                    "last_duration_ms":observation.duration_ms,
                    "iterations":observation.iterations,"failures":observation.failures,
                    "consecutive_failures":observation.consecutive_failures,
                    "termination":observation.termination
                })
            })
            .collect();
        Ok(
            json!({"process_id":self.process,"uptime_ms":millis(now.saturating_duration_since(self.started)),"components":components}),
        )
    }
}

/// Dropping the supervisor aborts its async loops; durable external-work journals
/// remain authoritative for requests interrupted by daemon exit.
pub struct Background {
    monitor: Arc<Monitor>,
    tasks: JoinSet<()>,
    names: BTreeMap<Id, Component>,
}
impl Background {
    pub fn new(monitor: Arc<Monitor>) -> Self {
        Self {
            monitor,
            tasks: JoinSet::new(),
            names: BTreeMap::new(),
        }
    }
    fn spawn(
        &mut self,
        component: Component,
        future: impl Future<Output = ()> + Send + 'static,
    ) -> Result<()> {
        self.monitor.register(component)?;
        let handle = self.tasks.spawn(future);
        self.names.insert(handle.id(), component);
        Ok(())
    }
    pub fn periodic<F, Fut>(
        &mut self,
        component: Component,
        initial_delay: Duration,
        delay: Duration,
        work: F,
    ) -> Result<()>
    where
        F: Fn() -> Fut + Send + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        self.periodic_woken(component, initial_delay, delay, None, work)
    }
    /// As `periodic`, but a `wake` notification also ends the delay early.
    pub fn periodic_woken<F, Fut>(
        &mut self,
        component: Component,
        initial_delay: Duration,
        delay: Duration,
        wake: Option<std::sync::Arc<crate::pickup::Pickup>>,
        work: F,
    ) -> Result<()>
    where
        F: Fn() -> Fut + Send + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        let monitor = self.monitor.clone();
        self.spawn(component, async move {
            tokio::time::sleep(initial_delay).await;
            loop {
                monitor.begin(component);
                let success = work().await.is_ok();
                monitor.finish(component, success);
                if !success {
                    eprintln!("{} reconciliation failed", component.name());
                }
                // Delay after completion: slow iterations never overlap or cause
                // catch-up bursts. Transient errors retain the existing retry rate.
                match (&wake, success) {
                    (Some(wake), true) => {
                        let _ = tokio::time::timeout(delay, wake.schedule().notified()).await;
                    }
                    _ => tokio::time::sleep(delay).await,
                }
            }
        })
    }
    pub async fn failure(&mut self) -> String {
        let (id, reason) = match self.tasks.join_next_with_id().await {
            Some(Ok((id, ()))) => (id, "returned"),
            Some(Err(error)) => (
                error.id(),
                if error.is_panic() {
                    "panicked"
                } else {
                    "cancelled"
                },
            ),
            None => return "no background tasks are registered".into(),
        };
        let component = self.names.remove(&id).expect("owned background task");
        self.monitor.terminated(component, reason);
        format!(
            "background component {} unexpectedly {reason}",
            component.name()
        )
    }
}

/// Both interactive runs and service-manager termination use the same exit path.
pub async fn shutdown_signal() -> std::io::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    tokio::select! { _=interrupt.recv()=>(), _=terminate.recv()=>() }
    Ok(())
}

#[cfg(test)]
#[path = "supervision_tests.rs"]
mod tests;
