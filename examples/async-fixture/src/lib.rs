//! Async-lift command fixture. It exports `wasi:cli/run@0.3.0`, whose `run` is
//! an async function, so the runtime must instantiate it with component-model
//! async and drive the task to completion.
wit_bindgen::generate!({
    path: "wit",
    world: "async-command",
    generate_all,
});

struct Command;

impl exports::wasi::cli::run::Guest for Command {
    async fn run() -> Result<(), ()> {
        // Yield once, so finishing `run` needs the runtime to resume the task.
        wit_bindgen::yield_async().await;
        Ok(())
    }
}

export!(Command);
