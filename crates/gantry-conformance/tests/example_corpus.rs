//! Executes the checked-in corpus and regression-tests the offline runner contract.

#[path = "../examples/support/mod.rs"]
mod support;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Value, json};

/// Turns a failed test operation into a contextual assertion without hiding errors.
fn checked<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| panic!("corpus test operation failed: {error:?}"))
}

/// Requires a runner rejection and retains its explanation for assertions.
fn rejected(result: Result<Vec<support::Report>, String>) -> String {
    match result {
        Err(error) => error,
        Ok(reports) => panic!("expected rejection, got {reports:?}"),
    }
}

/// Unique temporary package root, removed even when a test fails.
struct Package(PathBuf);
impl Package {
    /// Writes one self-contained source package and its metadata.
    fn new(source: &str, case: Value) -> Self {
        Self::raw(source, &checked(serde_json::to_vec(&case)))
    }

    /// Preserves raw metadata so duplicate keys reach the runner unchanged.
    fn raw(source: &str, case: &[u8]) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "gantry-corpus-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        checked(fs::create_dir(&root));
        checked(fs::write(root.join("main.gnt"), source));
        checked(fs::write(root.join("case.json"), case));
        Self(root)
    }
}
impl Drop for Package {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Case discovery remains rooted locally, independent of the test working directory.
#[test]
fn discovers_and_executes_checked_in_corpus() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples");
    let packages = checked(support::discover(&root));
    assert!(!packages.is_empty(), "checked-in corpus must not be empty");
    let mut failures = Vec::new();
    for package in packages {
        if let Err(error) = support::run_package(&package) {
            failures.push(error);
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Success metadata distinguishes missing expected from an explicit null result.
#[test]
fn pure_execution_and_multiple_scenarios() {
    let package = Package::new(
        "fn main() -> Int { 1 + 2 }",
        json!({"scenarios":[{"class":"cli","expected":3},{"class":"cli","expected":3}]}),
    );
    assert_eq!(
        checked(support::discover(&package.0)),
        std::slice::from_ref(&package.0)
    );
    assert_eq!(checked(support::run_package(&package.0)).len(), 2);
    let null = Package::new("fn main() {}", json!({"class":"cli","expected":null}));
    checked(support::run_package(&null.0));
}

/// Typed hooks record their requests and check exact public envelope metadata.
#[test]
fn prompt_dispatch_is_scripted_and_captured() {
    let package = Package::new(
        "agents { worker } default agent = worker; fn main() -> String { prompt \"offline\" -> String }",
        json!({"class":"host","expected":"done","hooks":[{"kind":"prompt","output":"done","assert_request":{"/operation_request/expected_type":"String"}}]}),
    );
    let reports = checked(support::run_package(&package.0));
    assert_eq!(reports[0].requests.len(), 1);
    assert_eq!(
        reports[0].requests[0]["operation_request"]["operation_kind"],
        "prompt"
    );
}

/// Wrong kinds and unused responses fail even when source handles host failures.
#[test]
fn rejects_wrong_kind_unconsumed_response_and_bad_assertion() {
    let source = "action read_only lookup() -> String; fn main() -> String { action lookup() }";
    for hook in [
        json!({"kind":"prompt","output":"done"}),
        json!({"kind":"action","output":"done","assert_request":{"/operation_request/expected_type":"Int"}}),
    ] {
        let package = Package::new(
            source,
            json!({"class":"host","expected":"done","hooks":[hook]}),
        );
        let error = rejected(support::run_package(&package.0));
        assert!(error.contains("script assertions"), "{error}");
    }
    let package = Package::new(
        "fn main() -> Int { 3 }",
        json!({"class":"cli","expected":3,"hooks":[{"kind":"action","output":3}]}),
    );
    assert!(rejected(support::run_package(&package.0)).contains("unconsumed"));
}

/// Typos and contradictory script data must never silently become default behavior.
#[test]
fn rejects_invalid_metadata() {
    for case in [
        json!({"class":"cli"}),
        json!({"class":"cli","expected":3,"typo":true}),
        json!({"scenarios":[]}),
        json!({"class":"concurrent"}),
        json!({"class":"concurrent","expected":null,"expected_error":"task-join-failure"}),
        json!({"class":"concurrent","expected":3,"expected_error":null}),
        json!({"class":"concurrent","expected_error":"task-join-failure","expected_diagnostic":"bad"}),
        json!({"class":"cli","expected":3,"expected_terminal":"not-a-category"}),
        json!({"class":"cli","expected":3,"expected_terminal":null}),
        json!({"class":"cli","expected":3,"expected_terminal":42}),
        json!({"class":"negative","expected_diagnostic":"bad","expected_terminal":"success"}),
        json!({"class":"runtime-failure","expected_error":"integer-division-by-zero","expected_terminal":"integer-division-by-zero"}),
        json!({"class":"host","expected":3,"hooks":[{"kind":"action","output":3,"error":"timeout"}]}),
        json!({"class":"host","expected":3,"hooks":[{"kind":"action","error":"not-a-code"}]}),
    ] {
        let package = Package::new("fn main() -> Int { 3 }", case);
        assert!(support::read_cases(&package.0).is_err());
    }
}

/// A runtime failure is checked against its stable wire code, not display text.
#[test]
fn checks_runtime_failure_code() {
    let package = Package::new(
        "fn main() -> Int { 1 / 0 }",
        json!({"class":"runtime-failure","expected_error":"integer-division-by-zero"}),
    );
    checked(support::run_package(&package.0));
}

/// Concurrent failures match the exact foreground code and its terminal category.
#[test]
fn concurrent_failure_checks_both_outcomes() {
    let source = "fn main() -> Int { spawn child -> Int { 1 / 0 } join(child) }";
    let package = Package::new(
        source,
        json!({"class":"concurrent","expected_error":"task-join-failure"}),
    );
    checked(support::run_package(&package.0));
    let wrong = Package::new(
        source,
        json!({"class":"concurrent","expected_error":"policy-denied"}),
    );
    assert!(rejected(support::run_package(&wrong.0)).contains("unexpected foreground"));
    let wrong_terminal = Package::new(
        source,
        json!({"class":"concurrent","expected_error":"task-join-failure","expected_terminal":"success"}),
    );
    assert!(rejected(support::run_package(&wrong_terminal.0)).contains("expected terminal"));
}

/// Successful foreground values cannot mask failed detached work, even durably.
#[test]
fn terminal_expectations_are_checked_for_ordinary_and_durable_runs() {
    let source = "fn main() -> Int { spawn child -> Int { 1 / 0 } detach(child); 42 }";
    for class in ["concurrent", "durable"] {
        for terminal in [None, Some("success"), Some("detached-task-failure")] {
            let mut case = json!({"class":class,"expected":42});
            if class == "durable" {
                case["durable_mode"] = json!("start-only");
            }
            if let Some(terminal) = terminal {
                case["expected_terminal"] = json!(terminal);
            }
            let package = Package::new(source, case);
            let result = support::run_package(&package.0);
            if terminal == Some("detached-task-failure") {
                checked(result);
            } else {
                assert!(rejected(result).contains("expected terminal"));
            }
        }
        let package = Package::new(
            "fn main() -> Int { 42 }",
            json!({"class":class,"expected":42,"expected_terminal":"detached-task-failure"}),
        );
        assert!(rejected(support::run_package(&package.0)).contains("expected terminal"));
    }
}

/// Strict decoding rejects repeated decoded keys at every raw JSON nesting level.
#[test]
fn rejects_recursive_duplicate_metadata_keys() {
    for raw in [
        r#"{"class":"cli","expected":1,"expected":2}"#,
        r#"{"scenarios":[{"class":"cli","expected":1,"expected":2}]}"#,
        r#"{"class":"host","expected":1,"hooks":[{"kind":"action","kind":"prompt","output":1}]}"#,
        r#"{"class":"host","expected":1,"hooks":[{"kind":"action","output":{"x":1,"\u0078":2}}]}"#,
        r#"{"class":"host","expected":1,"hooks":[{"kind":"action","output":1,"assert_request":{"/x":1,"/x":2}}]}"#,
        r#"{"class":"cli","expected":{"nested":[{"x":1,"x":2}]}}"#,
        r#"{"class":"cli","input":{"x":1,"x":2},"expected":1}"#,
    ] {
        let package = Package::raw("fn main() -> Int { 1 }", raw.as_bytes());
        let error = match support::read_cases(&package.0) {
            Err(error) => error,
            Ok(cases) => panic!("duplicate metadata accepted: {cases:?}"),
        };
        assert!(error.contains("DuplicateMember"), "{error}");
    }
}

/// Analysis uses exact diagnostic codes and does not execute invalid packages.
#[test]
fn negative_analysis_requires_the_named_diagnostic() {
    let source = "struct Pair<T, T> { value: T } fn main() {}";
    let package = Package::new(
        source,
        json!({"class":"negative","expected_diagnostic":"duplicate-type-parameter"}),
    );
    checked(support::run_package(&package.0));
    let wrong = Package::new(
        source,
        json!({"class":"negative","expected_diagnostic":"wrong-code"}),
    );
    assert!(rejected(support::run_package(&wrong.0)).contains("expected diagnostic"));
}

/// Public execution accepts entry JSON, joins children, and maps typed hook failures.
#[test]
fn input_concurrent_and_hook_failure_execution() {
    let input = Package::new(
        "fn main(value: Int) -> Int { value + 1 }",
        json!({"class":"cli","input":41,"expected":42}),
    );
    checked(support::run_package(&input.0));
    let concurrent = Package::new(
        "fn main() -> Int { spawn child -> Int { 7 } join(child) }",
        json!({"class":"concurrent","expected":7}),
    );
    checked(support::run_package(&concurrent.0));
    let failure = Package::new(
        "action read_only lookup() -> Int; fn main() -> Int { action lookup() }",
        json!({"class":"runtime-failure","expected_error":"policy-denied","hooks":[{"kind":"action","error":"policy-denied"}]}),
    );
    checked(support::run_package(&failure.0));
}

/// Decisions use the real sealed-output decoder rather than a mocked result value.
#[test]
fn decision_dispatch_uses_typed_output() {
    let package = Package::new(
        "agents { worker } default agent = worker; fn main() { discard decide \"Proceed?\"; }",
        json!({"class":"host","expected":null,"hooks":[{"kind":"decide","output":{"decision":true,"rationale":"ready"}}]}),
    );
    let reports = checked(support::run_package(&package.0));
    assert_eq!(
        reports[0].requests[0]["operation_request"]["operation_kind"],
        "decide"
    );
}
