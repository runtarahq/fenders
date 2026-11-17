//! Versioned, bundled examples. Selection uses ordinary upload admission and
//! never manufactures a validation receipt or starts an execution.
use crate::{
    db::{conflict, fields, s},
    error::{Error, Result},
    model::{Principal, digest},
    store::Store,
};
use serde_json::{Value, json};
pub struct Demo {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub filename: &'static str,
    pub bytes: &'static [u8],
}
pub const DEMOS: &[Demo] = &[
    Demo {
        id: "hello-http-v1",
        name: "HTTP hello",
        description: "Returns a plain-text greeting when you send a request.",
        filename: "hello-http.wasm",
        bytes: include_bytes!("../demos/hello-http-v1.wasm"),
    },
    Demo {
        id: "hello-command-v1",
        name: "Hello command",
        description: "Prints a greeting and exits when you run it manually or on a schedule.",
        filename: "hello-command.wasm",
        bytes: include_bytes!("../demos/hello-command-v1.wasm"),
    },
];
impl Store {
    pub async fn demo_components(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
    ) -> Result<Value> {
        let mut tx = self.transaction(false, false).await?;
        Self::project(&mut tx, p, tenant, project, false).await?;
        Ok(
            json!({"items":DEMOS.iter().map(|d|json!({"id":d.id,"name":d.name,"description":d.description,"filename":d.filename,"bytes":d.bytes.len(),"digest":digest(d.bytes)})).collect::<Vec<_>>()}),
        )
    }
    pub async fn select_demo(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        id: &str,
        value: Value,
    ) -> Result<Value> {
        let mut tx = self.transaction(false, false).await?;
        Self::project(&mut tx, p, tenant, project, true).await?;
        drop(tx);
        fields(&value, &["digest"], &["digest"])?;
        let demo = DEMOS
            .iter()
            .find(|d| d.id == id)
            .ok_or_else(Error::missing)?;
        if s(&value["digest"]) != digest(demo.bytes) {
            return Err(conflict("demo component changed; refresh the demo catalog"));
        }
        self.upload(p, tenant, project, demo.bytes).await
    }
}
