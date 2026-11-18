//! The contract, held to what the API answers.
//!
//! One test makes a request of every operation `openapi.json` describes and
//! checks each answer against the schema the contract gives for its status.
//! An operation the tour does not reach fails it, so a route added to the
//! contract is added here; a field that changes type, or a required one
//! that goes, fails it too.
use super::*;
use std::collections::{BTreeMap, BTreeSet};

fn spec() -> Value {
    serde_json::from_str(include_str!("../../static/api/openapi.json")).unwrap()
}

/// The schema keywords the contract uses. One it uses that is not here is a
/// failure, not a pass: nothing is skipped for not being understood.
fn check(spec: &Value, schema: &Value, value: &Value, at: &str, wrong: &mut Vec<String>) {
    let Some(schema) = schema.as_object() else {
        panic!("{at}: a schema is an object, not {schema}");
    };
    if let Some(pointer) = schema.get("$ref") {
        let pointer = pointer.as_str().unwrap();
        let target = spec
            .pointer(pointer.trim_start_matches('#'))
            .unwrap_or_else(|| panic!("{at}: {pointer} is nothing"));
        return check(spec, target, value, at, wrong);
    }
    macro_rules! fail {
        ($($message:tt)*) => {
            wrong.push(format!("{at}: {}", format!($($message)*)))
        };
    }
    for (keyword, rule) in schema {
        match keyword.as_str() {
            // Said for a reader, or of a request: nothing to hold an answer to.
            "description" | "default" | "deprecated" | "writeOnly" => {}
            "type" => {
                let is = |name: &str| match name {
                    "object" => value.is_object(),
                    "array" => value.is_array(),
                    "string" => value.is_string(),
                    "boolean" => value.is_boolean(),
                    "null" => value.is_null(),
                    "integer" => value.is_i64() || value.is_u64(),
                    "number" => value.is_number(),
                    other => panic!("{at}: unknown type {other}"),
                };
                if !is(rule.as_str().unwrap()) {
                    fail!("expected {rule}, found {value}");
                }
            }
            "enum" => {
                if !rule.as_array().unwrap().contains(value) {
                    fail!("{value} is not one of {rule}");
                }
            }
            "const" => {
                if rule != value {
                    fail!("{value} is not {rule}");
                }
            }
            "anyOf" | "oneOf" => {
                let passing = rule
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|option| {
                        let mut inner = Vec::new();
                        check(spec, option, value, at, &mut inner);
                        inner.is_empty()
                    })
                    .count();
                if passing == 0 || (keyword == "oneOf" && passing != 1) {
                    fail!("{value} matches {passing} of {keyword}");
                }
            }
            "properties" => {
                if let Some(object) = value.as_object() {
                    for (name, property) in rule.as_object().unwrap() {
                        if let Some(inner) = object.get(name) {
                            check(spec, property, inner, &format!("{at}.{name}"), wrong);
                        }
                    }
                }
            }
            "required" => {
                if let Some(object) = value.as_object() {
                    for name in rule.as_array().unwrap() {
                        if !object.contains_key(name.as_str().unwrap()) {
                            wrong.push(format!("{at}: {name} is required and missing"));
                        }
                    }
                }
            }
            "additionalProperties" => {
                if let Some(object) = value.as_object() {
                    let known = schema.get("properties").and_then(Value::as_object);
                    for (name, inner) in object {
                        if known.is_some_and(|known| known.contains_key(name)) {
                            continue;
                        }
                        match rule {
                            Value::Bool(true) => {}
                            Value::Bool(false) => {
                                wrong.push(format!("{at}: {name} is not a property"))
                            }
                            rule => check(spec, rule, inner, &format!("{at}.{name}"), wrong),
                        }
                    }
                }
            }
            "items" => {
                if let Some(items) = value.as_array() {
                    for (index, item) in items.iter().enumerate() {
                        check(spec, rule, item, &format!("{at}[{index}]"), wrong);
                    }
                }
            }
            "minItems" | "maxItems" => {
                if let Some(items) = value.as_array() {
                    let (length, bound) = (items.len() as u64, rule.as_u64().unwrap());
                    if (keyword == "minItems" && length < bound)
                        || (keyword == "maxItems" && length > bound)
                    {
                        fail!("{length} items, {keyword} {bound}");
                    }
                }
            }
            "minLength" | "maxLength" => {
                if let Some(text) = value.as_str() {
                    let (length, bound) = (text.chars().count() as u64, rule.as_u64().unwrap());
                    if (keyword == "minLength" && length < bound)
                        || (keyword == "maxLength" && length > bound)
                    {
                        fail!("{length} characters, {keyword} {bound}");
                    }
                }
            }
            "minimum" | "maximum" => {
                if let Some(number) = value.as_f64() {
                    let bound = rule.as_f64().unwrap();
                    if (keyword == "minimum" && number < bound)
                        || (keyword == "maximum" && number > bound)
                    {
                        fail!("{number}, {keyword} {bound}");
                    }
                }
            }
            "pattern" => {
                if let Some(text) = value.as_str() {
                    let hex = |length: usize| {
                        text.len() == length
                            && text
                                .bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    };
                    // The patterns the contract has; another is to be added
                    // here with what it means.
                    let matches = match rule.as_str().unwrap() {
                        "^[0-9a-f]{32}$" => hex(32),
                        "^[0-9a-f]{64}$" => hex(64),
                        "^[a-z][a-z0-9-]{0,62}$" => {
                            fenders_control_plane::model::name(text).is_ok()
                        }
                        other => panic!("{at}: unknown pattern {other}"),
                    };
                    if !matches {
                        fail!("{value} does not match {rule}");
                    }
                }
            }
            "format" => {
                if let Some(text) = value.as_str() {
                    let fits = match rule.as_str().unwrap() {
                        "date-time" => chrono::DateTime::parse_from_rfc3339(text).is_ok(),
                        "uri" => text.contains("://"),
                        "binary" => true,
                        other => panic!("{at}: unknown format {other}"),
                    };
                    if !fits {
                        fail!("{value} is not a {rule}");
                    }
                }
            }
            other => panic!("{at}: the contract uses {other}, which this test does not check"),
        }
    }
}

#[test]
fn the_checker_refuses_what_a_schema_forbids() {
    let spec =
        json!({"components":{"schemas":{"Id":{"type":"string","pattern":"^[0-9a-f]{32}$"}}}});
    let schema = json!({"type":"object","required":["id","state"],"properties":{
        "id":{"$ref":"#/components/schemas/Id"},
        "state":{"type":"string","enum":["pending","succeeded"]},
        "error":{"anyOf":[{"type":"string"},{"type":"null"}]},
        "created":{"type":"string","format":"date-time"},
        "items":{"type":"array","items":{"type":"integer","minimum":1}}}});
    let wrong = |value: Value| {
        let mut wrong = Vec::new();
        check(&spec, &schema, &value, "$", &mut wrong);
        wrong
    };
    let id = "0123456789abcdef0123456789abcdef";
    assert!(
        wrong(json!({"id":id,"state":"pending","error":null,"more":1,
        "created":"2026-11-18T19:00:00.5+00:00","items":[1,2]}))
        .is_empty()
    );
    for (broken, count) in [
        (json!({"state":"pending"}), 1),
        (json!({"id":"short","state":"pending"}), 1),
        (json!({"id":id,"state":"unknown"}), 1),
        (json!({"id":id,"state":"pending","error":7}), 1),
        (json!({"id":id,"state":"pending","created":"yesterday"}), 1),
        (json!({"id":id,"state":"pending","items":[1,0,"x"]}), 2),
        (json!([]), 1),
    ] {
        assert_eq!(wrong(broken.clone()).len(), count, "{broken}");
    }
}

/// The keywords [`check`] knows, and the ones that only describe.
const KEYWORDS: [&str; 22] = [
    "$ref",
    "type",
    "enum",
    "const",
    "anyOf",
    "oneOf",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "minItems",
    "maxItems",
    "minLength",
    "maxLength",
    "minimum",
    "maximum",
    "pattern",
    "format",
    "description",
    "default",
    "deprecated",
    "writeOnly",
];

/// Every schema in `value`, a request's as much as an answer's.
fn schemas<'a>(value: &'a Value, is_schema: bool, found: &mut Vec<&'a Value>) {
    match value {
        Value::Object(map) => {
            if is_schema {
                found.push(value);
            }
            for (key, inner) in map {
                let inner_is_schema = match key.as_str() {
                    // A map from names to schemas.
                    "properties" | "schemas" if is_schema || key == "schemas" => {
                        for schema in inner.as_object().unwrap().values() {
                            schemas(schema, true, found);
                        }
                        continue;
                    }
                    "schema" | "items" => true,
                    "additionalProperties" => inner.is_object(),
                    "anyOf" | "oneOf" if is_schema => {
                        for schema in inner.as_array().unwrap() {
                            schemas(schema, true, found);
                        }
                        continue;
                    }
                    _ if is_schema => continue,
                    _ => false,
                };
                schemas(inner, inner_is_schema, found);
            }
        }
        Value::Array(items) => items.iter().for_each(|item| schemas(item, false, found)),
        _ => {}
    }
}

#[test]
fn the_contract_is_made_of_what_the_checker_knows() {
    let spec = spec();
    let mut found = Vec::new();
    schemas(&spec, false, &mut found);
    assert!(found.len() > 500, "{}", found.len());
    for schema in found {
        for keyword in schema.as_object().unwrap().keys() {
            assert!(
                KEYWORDS.contains(&keyword.as_str()),
                "a schema uses {keyword}, which nothing here checks: {schema}"
            );
        }
        // A type is one of JSON's, and an object's required names are its own.
        if let Some(kind) = schema.get("type") {
            let kinds = [
                "object", "array", "string", "integer", "number", "boolean", "null",
            ];
            assert!(kinds.contains(&kind.as_str().unwrap()), "{schema}");
        }
        if let (Some(required), Some(properties)) =
            (schema.get("required"), schema.get("properties"))
        {
            for name in required.as_array().unwrap() {
                assert!(
                    properties.get(name.as_str().unwrap()).is_some(),
                    "{name} is required and is no property: {schema}"
                );
            }
        }
    }
    // An operation has an id of its own, a summary, and a tag.
    let mut ids = BTreeSet::new();
    for (path, methods) in spec["paths"].as_object().unwrap() {
        for (method, operation) in methods.as_object().unwrap() {
            let id = operation["operationId"].as_str().unwrap();
            assert!(ids.insert(id), "{id} names two operations");
            assert!(
                operation["summary"]
                    .as_str()
                    .is_some_and(|text| !text.is_empty()),
                "{method} {path} has no summary"
            );
        }
    }
}

/// Checks one answer the API gave, from any test, against the contract:
/// the tour below asks every operation once, and the other tests ask them
/// in states the tour does not reach (a run on a node, an app being
/// replaced). A path that is no route of the contract is not checked.
pub(crate) fn conforms(method: &str, path: &str, status: StatusCode, body: &Value) {
    static SPEC: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    let spec = SPEC.get_or_init(spec);
    let method = method.to_lowercase();
    let path = path.split('?').next().unwrap();
    // The names the control plane has for the workspace's routes are
    // answered as the public ones are.
    let public = path
        .replacen("/v1/tenants/", "/v1/workspaces/", 1)
        .replace("/external-endpoints", "/connections");
    let found = operation(spec, &method, path).or_else(|| operation(spec, &method, &public));
    let Some((template, operation)) = found else {
        return;
    };
    // What each answer was, for writing the contract from.
    if let Ok(file) = std::env::var("FENDERS_CONTRACT_DUMP") {
        use std::io::Write;
        let line =
            json!({"method":method,"template":template,"status":status.as_u16(),"body":body});
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(file)
            .unwrap();
        writeln!(file, "{line}").unwrap();
        return;
    }
    let at = format!("{method} {path} -> {}", status.as_u16());
    let responses = &operation["responses"];
    let code = status.as_u16().to_string();
    assert!(
        !status.is_success() || responses.get(&code).is_some(),
        "{at}: the contract gives {template} no {code}"
    );
    let mut response = responses.get(&code).unwrap_or(&responses["default"]);
    if let Some(pointer) = response["$ref"].as_str() {
        response = spec.pointer(pointer.trim_start_matches('#')).unwrap();
    }
    let mut wrong = Vec::new();
    check(
        spec,
        &response["content"]["application/json"]["schema"],
        body,
        &at,
        &mut wrong,
    );
    assert!(
        wrong.is_empty(),
        "an answer differs from the contract:\n{}",
        wrong.join("\n")
    );
}

/// What was asked and what came back.
struct Seen {
    method: String,
    path: String,
    status: StatusCode,
    body: Value,
}

struct Tour<'a> {
    l: &'a Lab,
    seen: Vec<Seen>,
}
impl Tour<'_> {
    async fn send(&mut self, token: &str, method: &str, path: &str, body: Option<Value>) -> Value {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("Authorization", format!("Bearer {token}"));
        if !matches!(method, "GET") {
            request = request.header("Idempotency-Key", uid());
        }
        let body = match body {
            Some(Value::String(component)) => {
                request = request.header("Content-Type", "application/wasm");
                Body::from(component.into_bytes())
            }
            Some(body) => {
                request = request.header("Content-Type", "application/json");
                Body::from(body.to_string())
            }
            None => Body::empty(),
        };
        let response = api::router(self.l.store.clone())
            .oneshot(request.body(body).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4 << 20).await.unwrap())
                .unwrap();
        self.seen.push(Seen {
            method: method.to_lowercase(),
            path: path.split('?').next().unwrap().to_owned(),
            status,
            body: body.clone(),
        });
        body
    }
    /// A request that is answered, not refused.
    async fn ok(&mut self, token: &str, method: &str, path: &str, body: Option<Value>) -> Value {
        let answer = self.send(token, method, path, body).await;
        let status = self.seen.last().unwrap().status;
        assert!(status.is_success(), "{method} {path}: {status} {answer}");
        answer
    }
}

/// The contract's operation for a request: its path's template, by the
/// template that names the most of the path literally.
fn operation<'a>(spec: &'a Value, method: &str, path: &str) -> Option<(&'a str, &'a Value)> {
    let path: Vec<&str> = path.trim_start_matches("/v1").split('/').collect();
    spec["paths"]
        .as_object()
        .unwrap()
        .iter()
        .filter(|(_, methods)| methods.get(method).is_some())
        .filter_map(|(template, methods)| {
            let segments: Vec<&str> = template.split('/').collect();
            (segments.len() == path.len()
                && segments
                    .iter()
                    .zip(&path)
                    .all(|(t, p)| t.starts_with('{') || t == p))
            .then(|| {
                let literal = segments.iter().filter(|t| !t.starts_with('{')).count();
                (literal, template.as_str(), &methods[method])
            })
        })
        .max_by_key(|(literal, _, _)| *literal)
        .map(|(_, template, operation)| (template, operation))
}

#[tokio::test]
async fn every_operation_answers_as_the_contract_says() {
    let l = Lab::new().await;
    let spec = spec();
    let operator = l.token.clone();
    let mut t = Tour {
        l: &l,
        seen: Vec::new(),
    };

    // The operator's routes.
    let allowance = json!({"cpu_percent":200,"memory_mib":1024,"storage_bytes":1073741824,"instances":2,"transfer_bytes":1073741824});
    let other = t
        .ok(
            &operator,
            "POST",
            "/v1/tenants",
            Some(json!({"name":"other","allowance":allowance})),
        )
        .await;
    let other = format!("/v1/tenants/{}", s(&other["id"]));
    t.ok(
        &operator,
        "PATCH",
        &other,
        Some(json!({"default_app_size":"medium","allowance":allowance})),
    )
    .await;
    t.ok(
        &operator,
        "PATCH",
        &format!("{other}/http-limits"),
        Some(json!({"concurrent_requests":8,"requests_per_minute":120})),
    )
    .await;
    t.ok(
        &operator,
        "POST",
        &format!("{other}/lifecycle"),
        Some(json!({"action":"suspend","reason":"Toured","expected_revision":1})),
    )
    .await;
    let tenant = format!("/v1/tenants/{}", l.tenant);
    let issue = json!({"name":"tour","project_id":null,"permissions":["read","apps:write","runs:write","projects:write","connections:write","secrets:write"],"ttl_seconds":3600,"label":"tour"});
    // Issued, and then asked for again with the same key: two answers of
    // one operation, the second without a token.
    let mut issued = Value::Null;
    for expected in [StatusCode::CREATED, StatusCode::OK] {
        let response = api::router(l.store.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("{tenant}/api-keys"))
                    .header("Authorization", format!("Bearer {operator}"))
                    .header("Idempotency-Key", "tour-key")
                    .header("Content-Type", "application/json")
                    .body(Body::from(issue.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap();
        t.seen.push(Seen {
            method: "post".into(),
            path: format!("{tenant}/api-keys"),
            status: expected,
            body: body.clone(),
        });
        if expected == StatusCode::CREATED {
            issued = body;
        }
    }
    let key = s(&issued["token"]).to_owned();
    let spare = t
        .ok(
            &operator,
            "POST",
            &format!("{tenant}/api-keys"),
            Some(json!({"name":"spare","permissions":["read"],"ttl_seconds":60})),
        )
        .await;
    t.ok(&operator, "GET", &format!("{tenant}/api-keys"), None)
        .await;
    t.ok(
        &operator,
        "DELETE",
        &format!("{tenant}/api-keys/{}", s(&spare["id"])),
        None,
    )
    .await;
    let node = t
        .ok(&operator, "POST", "/v1/nodes", Some(json!({"name":"node-1","cert_sha256":"a".repeat(64),"endpoint":"https://node-1.internal:9443","backend":"wasm","architecture":"x86_64","runtime":"wasmtime-50.0.0-fenders-v1","cpu_percent":200,"memory_mib":1024,"instances":4})))
        .await;
    t.ok(&operator, "GET", "/v1/nodes", None).await;
    t.ok(
        &operator,
        "PATCH",
        &format!("/v1/nodes/{}", s(&node["id"])),
        Some(json!({"draining":true})),
    )
    .await;
    let policy = t
        .ok(&operator, "GET", "/v1/public-egress-policy", None)
        .await;
    t.ok(
        &operator,
        "PUT",
        "/v1/public-egress-policy",
        Some(json!({"expected_revision":policy["revision"],"enabled":false})),
    )
    .await;
    t.ok(&operator, "GET", "/v1/control-plane/status", None)
        .await;

    // The workspace API, with a key, and once as the operator where the
    // two are answered differently.
    let w = format!("/v1/workspaces/{}", l.tenant);
    let p = format!("{w}/projects/{}", l.project);
    t.ok(&key, "GET", "/v1/me", None).await;
    t.ok(&operator, "GET", "/v1/me", None).await;
    t.ok(&key, "GET", "/v1/workspaces", None).await;
    t.ok(&operator, "GET", "/v1/workspaces", None).await;
    t.ok(&key, "GET", &format!("{w}/projects"), None).await;
    t.ok(
        &key,
        "POST",
        &format!("{w}/projects"),
        Some(json!({"name":"Toured"})),
    )
    .await;
    for scope in [&w, &p] {
        t.ok(&key, "GET", &format!("{scope}/usage"), None).await;
        t.ok(&key, "GET", &format!("{scope}/usage/history"), None)
            .await;
    }
    t.ok(&key, "GET", &format!("{p}/app-sizes"), None).await;
    t.ok(&key, "GET", &format!("{p}/https-access"), None).await;
    t.ok(
        &key,
        "POST",
        &format!("{p}/https-access/validate"),
        Some(json!({"origins":["https://example.com"]})),
    )
    .await;
    t.ok(
        &key,
        "POST",
        &format!("{p}/schedules/preview"),
        Some(json!({"expression":"*/5 * * * *","timezone":"UTC"})),
    )
    .await;

    // Artifacts. No node inspects here: the lab says of them what one would.
    let second = t
        .ok(
            &key,
            "POST",
            &format!("{p}/artifacts"),
            Some(json!("\0asm\x0d\0\x01\0 second")),
        )
        .await;
    let second = s(&second["id"]).to_owned();
    t.ok(&key, "GET", &format!("{p}/artifacts"), None).await;
    t.ok(&key, "GET", &format!("{p}/artifacts/{second}"), None)
        .await;
    t.ok(
        &key,
        "GET",
        &format!("{p}/artifacts/{second}/inspection"),
        None,
    )
    .await;
    l.validated().await;
    sqlx::query("UPDATE artifact_validations v SET state='valid',lease_until=NULL,updated=now(),inspection=jsonb_build_object('format_version',1,'runtime',$2::text,'digest',a.digest,'bytes',a.size,'http',true,'command',true,'imports','[]'::jsonb,'exports','[]'::jsonb) FROM artifacts a WHERE a.id=v.artifact_id AND a.id=$1")
        .bind(&second)
        .bind(fenders_control_plane::artifacts::RUNTIME)
        .execute(&l.store.pool)
        .await
        .unwrap();
    t.ok(
        &key,
        "GET",
        &format!("{p}/artifacts/{second}/inspection"),
        None,
    )
    .await;

    // Secrets and connections.
    let secret = t
        .ok(
            &key,
            "POST",
            &format!("{p}/secrets"),
            Some(json!({"name":"token","value":"hunter22"})),
        )
        .await;
    t.ok(&key, "GET", &format!("{p}/secrets"), None).await;
    t.ok(
        &key,
        "GET",
        &format!("{p}/secrets/{}", s(&secret["id"])),
        None,
    )
    .await;
    let connect = "tour connect";
    let connection = {
        let response = api::router(l.store.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("{p}/connections"))
                    .header("Authorization", format!("Bearer {key}"))
                    .header("Idempotency-Key", connect)
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        json!({"type":"https","name":"example","origin":"https://example.com"})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap();
        assert!(status.is_success(), "{body}");
        t.seen.push(Seen {
            method: "post".into(),
            path: format!("{p}/connections"),
            status,
            body: body.clone(),
        });
        s(&body["resource_id"]).to_owned()
    };
    t.ok(
        &key,
        "GET",
        &format!("{p}/endpoint-submissions/tour%20connect"),
        None,
    )
    .await;
    t.ok(&key, "GET", &format!("{p}/connections"), None).await;
    t.ok(&key, "GET", &format!("{p}/connections/{connection}"), None)
        .await;

    // Apps: a draft, then one deployed with a schedule, and one served
    // over HTTP, which with no node stays pending.
    let draft = t
        .ok(
            &key,
            "POST",
            &format!("{p}/apps"),
            Some(json!({"name":"draft","artifact_id":l.artifact})),
        )
        .await;
    let deployed = {
        let response = api::router(l.store.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("{p}/apps/deploy"))
                    .header("Authorization", format!("Bearer {key}"))
                    .header("Idempotency-Key", "tour-deploy")
                    .header("Content-Type", "application/json")
                    .body(Body::from(json!({"name":"job","artifact_id":l.artifact,
                        "configuration":{"size":"small","env":{"MODE":"tour"},"secret_env":{"TOKEN":secret["id"]}},
                        "triggers":{"manual":true,"http":false,"schedule":{"enabled":true,"expression":"0 * * * *","timezone":"UTC"}}}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap();
        assert!(status.is_success(), "{body}");
        t.seen.push(Seen {
            method: "post".into(),
            path: format!("{p}/apps/deploy"),
            status,
            body: body.clone(),
        });
        body
    };
    let web = t
        .ok(&key, "POST", &format!("{p}/apps/deploy"), Some(json!({"name":"web","artifact_id":l.artifact,"triggers":{"manual":false,"http":true}})))
        .await;
    assert_eq!(t.seen.last().unwrap().status, StatusCode::ACCEPTED);
    t.ok(
        &key,
        "GET",
        &format!("{p}/app-submissions/tour-deploy"),
        None,
    )
    .await;
    let app = format!("{p}/apps/{}", s(&deployed["resource_id"]));
    let web = format!("{p}/apps/{}", s(&web["resource_id"]));
    let draft = format!("{p}/apps/{}", s(&draft["resource_id"]));
    t.ok(&key, "GET", &format!("{p}/apps"), None).await;
    for one in [&app, &web, &draft] {
        t.ok(&key, "GET", one, None).await;
        t.ok(&key, "GET", &format!("{one}/triggers"), None).await;
        t.ok(&key, "GET", &format!("{one}/http"), None).await;
        t.ok(&key, "GET", &format!("{one}/websocket"), None).await;
        t.ok(&key, "GET", &format!("{one}/connections"), None).await;
    }
    let revision = async |l: &Lab, app: &str| {
        let id = app.rsplit('/').next().unwrap();
        l.store
            .app(&l.operator, &l.tenant, &l.project, id)
            .await
            .unwrap()["revision"]
            .clone()
    };

    // Versions and releases.
    let version = t
        .ok(
            &key,
            "POST",
            &format!("{app}/versions"),
            Some(json!({"artifact_id":second,"expected_revision":revision(&l, &app).await})),
        )
        .await;
    let versions = t.ok(&key, "GET", &format!("{app}/versions"), None).await;
    assert_eq!(versions["items"].as_array().unwrap().len(), 2);
    t.ok(
        &key,
        "GET",
        &format!("{app}/versions/{}", s(&version["resource_id"])),
        None,
    )
    .await;
    let release = t
        .ok(&key, "POST", &format!("{app}/releases"), Some(json!({"version_id":version["resource_id"],"expected_revision":revision(&l, &app).await})))
        .await;
    t.ok(&key, "GET", &format!("{app}/releases"), None).await;
    t.ok(
        &key,
        "GET",
        &format!("{app}/releases/{}", s(&release["resource_id"])),
        None,
    )
    .await;

    // A run, which with no node waits; then cancelled.
    let run = {
        let response = api::router(l.store.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("{app}/runs"))
                    .header("Authorization", format!("Bearer {key}"))
                    .header("Idempotency-Key", "tour-run")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap();
        assert!(status.is_success(), "{body}");
        t.seen.push(Seen {
            method: "post".into(),
            path: format!("{app}/runs"),
            status,
            body: body.clone(),
        });
        s(&body["resource_id"]).to_owned()
    };
    t.ok(&key, "GET", &format!("{app}/submissions/tour-run"), None)
        .await;
    t.ok(&key, "GET", &format!("{app}/runs"), None).await;
    t.ok(&key, "GET", &format!("{app}/runs/{run}"), None).await;
    t.ok(&key, "GET", &format!("{app}/logs"), None).await;
    t.ok(&key, "GET", &format!("{app}/events"), None).await;
    t.ok(&key, "POST", &format!("{app}/runs/{run}/cancel"), None)
        .await;
    t.ok(&key, "GET", &format!("{app}/runs/{run}"), None).await;
    t.ok(&key, "GET", &format!("{app}/events"), None).await;

    // Triggers, connections and lifecycle of the app.
    let triggers = t.ok(&key, "GET", &format!("{app}/triggers"), None).await;
    t.ok(&key, "PUT", &format!("{app}/triggers"), Some(json!({"manual":true,"schedule":{"enabled":false},"expected_revision":triggers["revision"]}))).await;
    t.ok(
        &key,
        "PUT",
        &format!("{app}/connections"),
        Some(json!({"connections":[],"expected_revision":revision(&l, &app).await})),
    )
    .await;
    t.ok(
        &key,
        "PATCH",
        &app,
        Some(json!({"desired":"stopped","expected_revision":revision(&l, &app).await})),
    )
    .await;
    t.ok(&key, "GET", &app, None).await;

    // One request of the HTTP app. Nothing serves it: the gateway says so.
    let sample = t
        .ok(&key, "POST", &format!("{web}/http-sample"), Some(json!({})))
        .await;
    assert_ne!(sample["outcome"], "response");

    // Operations, and the deletions.
    let operations = t.ok(&key, "GET", &format!("{p}/operations"), None).await;
    t.ok(
        &key,
        "GET",
        &format!("{p}/operations/{}", s(&operations[0]["id"])),
        None,
    )
    .await;
    t.ok(
        &key,
        "DELETE",
        &app,
        Some(json!({"expected_revision":revision(&l, &app).await})),
    )
    .await;
    t.ok(
        &key,
        "DELETE",
        &format!("{p}/connections/{connection}"),
        None,
    )
    .await;
    t.ok(&key, "GET", &format!("{p}/apps"), None).await;

    // Refusals are answers too.
    t.send(&key, "GET", &format!("{p}/apps/{}", uid()), None)
        .await;
    t.send(&key, "POST", "/v1/tenants", Some(json!({}))).await;
    t.send("nothing", "GET", "/v1/me", None).await;
    t.send(&key, "PUT", &format!("{w}/projects"), Some(json!({})))
        .await;

    if std::env::var("FENDERS_CONTRACT_DUMP").is_ok() {
        for seen in &t.seen {
            conforms(&seen.method, &seen.path, seen.status, &seen.body);
        }
    }

    // Every answer is what the contract says an answer of its status is.
    let mut wrong = Vec::new();
    let mut reached = BTreeSet::new();
    let mut statuses: BTreeMap<(String, String), BTreeSet<u16>> = BTreeMap::new();
    for seen in &t.seen {
        let at = format!("{} {} -> {}", seen.method, seen.path, seen.status.as_u16());
        let Some((template, operation)) = operation(&spec, &seen.method, &seen.path) else {
            // A method no route takes there: the refusal every path may give.
            assert_eq!(seen.status, StatusCode::METHOD_NOT_ALLOWED, "{at}");
            let schema = &spec["components"]["responses"]["MethodNotAllowed"]["content"]["application/json"]
                ["schema"];
            check(&spec, schema, &seen.body, &at, &mut wrong);
            continue;
        };
        let responses = &operation["responses"];
        let code = seen.status.as_u16().to_string();
        let mut response = responses.get(&code).unwrap_or(&responses["default"]);
        if seen.status.is_success() {
            assert!(
                responses.get(&code).is_some(),
                "{at}: the contract gives {template} no {code}"
            );
            reached.insert((seen.method.clone(), template.to_owned()));
            statuses
                .entry((seen.method.clone(), template.to_owned()))
                .or_default()
                .insert(seen.status.as_u16());
        }
        if let Some(pointer) = response["$ref"].as_str() {
            response = spec.pointer(pointer.trim_start_matches('#')).unwrap();
        }
        let schema = &response["content"]["application/json"]["schema"];
        check(&spec, schema, &seen.body, &at, &mut wrong);
    }
    assert!(
        wrong.is_empty(),
        "{} answers differ from the contract:\n{}",
        wrong.len(),
        wrong.join("\n")
    );

    // And every operation was asked.
    let mut unreached = Vec::new();
    for (template, methods) in spec["paths"].as_object().unwrap() {
        for method in methods.as_object().unwrap().keys() {
            if !reached.contains(&(method.clone(), template.clone())) {
                unreached.push(format!("{method} {template}"));
            }
        }
    }
    assert!(
        unreached.is_empty(),
        "the tour does not reach: {unreached:?}"
    );
    l.finish().await;
}
