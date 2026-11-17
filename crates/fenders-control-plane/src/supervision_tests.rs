use super::*;

async fn until(monitor: &Monitor, test: impl Fn(&Value) -> bool) -> Value {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let snapshot = monitor.snapshot().unwrap();
            if test(&snapshot) {
                break snapshot;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn transient_errors_are_observable_and_recover_without_overlapping_iterations() {
    let monitor = Arc::new(Monitor::default());
    let mut background = Background::new(monitor.clone());
    let (sender, receiver) = tokio::sync::mpsc::channel::<Result<()>>(2);
    let receiver = Arc::new(tokio::sync::Mutex::new(receiver));
    background
        .periodic(
            Component::Scheduler,
            Duration::ZERO,
            Duration::from_millis(1),
            move || {
                let receiver = receiver.clone();
                async move { receiver.lock().await.recv().await.unwrap() }
            },
        )
        .unwrap();
    let initial = until(&monitor, |v| v["components"][0]["state"] == "running").await;
    assert!(initial["components"][0]["last_success_age_ms"].is_null());
    assert_eq!(initial["components"][0]["iterations"], 0);
    sender
        .send(Err(Error::invalid("private provider detail")))
        .await
        .unwrap();
    let failed = until(&monitor, |v| v["components"][0]["iterations"] == 1).await;
    assert_eq!(failed["components"][0]["failures"], 1);
    assert_eq!(failed["components"][0]["consecutive_failures"], 1);
    assert!(failed["components"][0]["last_success_age_ms"].is_null());
    assert!(!failed.to_string().contains("private provider"));
    sender.send(Ok(())).await.unwrap();
    let recovered = until(&monitor, |v| {
        v["components"][0]["iterations"] == 2 && v["components"][0]["state"] == "running"
    })
    .await;
    assert_eq!(recovered["components"][0]["failures"], 1);
    assert_eq!(recovered["components"][0]["consecutive_failures"], 0);
    assert!(recovered["components"][0]["last_success_age_ms"].is_u64());
    // The third iteration is waiting for input: no fourth can overlap it.
    assert_eq!(recovered["components"].as_array().unwrap().len(), 1);
    assert_eq!(initial["process_id"], recovered["process_id"]);
    drop(background);
    tokio::time::timeout(Duration::from_secs(2), sender.closed())
        .await
        .unwrap();
}

#[tokio::test]
async fn unexpected_return_panic_and_cancellation_are_supervised_with_fixed_names() {
    for mode in ["returned", "panicked", "cancelled"] {
        let monitor = Arc::new(Monitor::default());
        let mut background = Background::new(monitor.clone());
        background
            .spawn(Component::PickupListener, async move {
                match mode {
                    "panicked" => panic!("supervision fixture panic"),
                    "cancelled" => std::future::pending().await,
                    _ => (),
                }
            })
            .unwrap();
        if mode == "cancelled" {
            background.tasks.abort_all();
        }
        let reason = tokio::time::timeout(Duration::from_secs(2), background.failure())
            .await
            .unwrap();
        assert_eq!(
            reason,
            format!("background component pickup_listener unexpectedly {mode}")
        );
        let snapshot = monitor.snapshot().unwrap();
        assert_eq!(snapshot["components"][0]["state"], "terminated");
        assert_eq!(snapshot["components"][0]["termination"], mode);
        assert_eq!(snapshot["components"][0]["iterations"], 0);
        assert!(!snapshot.to_string().contains("fixture panic"));
    }
}

#[tokio::test]
async fn registration_is_bounded_and_process_restart_cannot_reuse_old_health() {
    let monitor = Arc::new(Monitor::default());
    let mut background = Background::new(monitor.clone());
    assert_eq!(
        background.failure().await,
        "no background tasks are registered"
    );
    for component in [
        Component::Scheduler,
        Component::PickupListener,
        Component::InvitationEmail,
    ] {
        background.spawn(component, std::future::pending()).unwrap();
        assert!(background.spawn(component, std::future::pending()).is_err());
    }
    assert_eq!(
        monitor.snapshot().unwrap()["components"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    let fresh = Monitor::default().snapshot().unwrap();
    assert_ne!(
        fresh["process_id"],
        monitor.snapshot().unwrap()["process_id"]
    );
    assert_eq!(fresh["components"], json!([]));
}
