use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fs, process::Command};
const COMMAND: &str = r#"(component
 (core module $m (func (export "run") (result i32) i32.const 0))
 (core instance $i (instantiate $m))
 (func $run (result (result)) (canon lift (core func $i "run")))
 (instance $cli (export "run" (func $run)))
 (export "wasi:cli/run@0.2.0" (instance $cli)))"#;
#[test]
fn cli_returns_only_bounded_identity_bound_rejection_categories() {
    let excessive = COMMAND.replacen(
        "(export \"wasi:cli/run",
        &format!(
            "(export \"{}\" (instance $cli)) (export \"wasi:cli/run",
            "x".repeat(257)
        ),
        1,
    );
    let cases = [
        (b"\0asm\x0d\0\x01\0broken".to_vec(), "invalid-component"),
        (
            wat::parse_str("(component)").unwrap(),
            "incompatible-entry-points",
        ),
        (
            wat::parse_str(COMMAND.replace("(result (result))", "(result u32)")).unwrap(),
            "incompatible-entry-points",
        ),
        (
            wat::parse_str(COMMAND.replacen(
                "(component",
                "(component (import \"private:host/secret\" (instance (export \"call\" (func))))",
                1,
            ))
            .unwrap(),
            "unsupported-imports",
        ),
        (wat::parse_str(excessive).unwrap(), "interface-limits"),
    ];
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("input.wasm");
    let output = root.path().join("compiled");
    let metadata = root.path().join("inspection.json");
    for (bytes, code) in cases {
        fs::write(&input, &bytes).unwrap();
        let error = fenders_component::inspect(&bytes).unwrap_err();
        assert_eq!(fenders_component::rejection_code(&error), Some(code));
        for inspect in [false, true] {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_fenders-component"));
            if inspect {
                cmd.arg("inspect").arg(&input).arg(&metadata);
            } else {
                cmd.arg(&input).arg(&output).arg(&metadata);
            }
            let result = cmd.output().unwrap();
            assert_eq!(
                result.status.code(),
                Some(2),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            let receipt: Value = serde_json::from_slice(&fs::read(&metadata).unwrap()).unwrap();
            assert_eq!(receipt.as_object().unwrap().len(), 5);
            assert_eq!(receipt["error"], code);
            assert_eq!(receipt["bytes"], bytes.len());
            assert_eq!(receipt["digest"], format!("{:x}", Sha256::digest(&bytes)));
            assert_eq!(receipt["runtime"], fenders_component::RUNTIME);
            assert!(
                !fs::read_to_string(&metadata)
                    .unwrap()
                    .contains("private:host")
            );
            assert!(!output.exists());
        }
    }
    assert!(
        fenders_component::rejection_code(&anyhow::anyhow!(
            "unsupported-imports: infrastructure text"
        ))
        .is_none()
    );
    // Input I/O failure is not a permanent component rejection.
    fs::remove_file(&input).unwrap();
    fs::remove_file(&metadata).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_fenders-component"))
        .arg("inspect")
        .arg(&input)
        .arg(&metadata)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert!(!metadata.exists());
}
