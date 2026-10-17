//! `gantry test`: one bounded unit test workflow over one package.
//!
//! This module is the presentation boundary of the experimental test workflow owned by
//! `GNT-GP-TOOLING-RUNTIME-001`. It parses `test --max-transitions N [--json] [PACKAGE_ROOT]`,
//! asks the facade for one complete report, and publishes that report within the contract's
//! 1 MiB encoded ceiling. It owns no language semantics: the facade decides preflight, admission,
//! execution, and the exit-class judgment, and this module only maps the judgment to an exit code
//! and to the two output formats.
//!
//! Exit codes are the contract's: `0` only for clean completion, `1` for invalid source or a fixed
//! test failure, `2` for admission, operational, no-tests, exhaustion, or cancellation, and `64`
//! for malformed usage. A JSON run writes exactly one document or nothing: the encoded document is
//! fully built and checked against the ceiling before the first byte is written, so an over-ceiling
//! report can never appear as a truncated success.

use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;

use gantry::host::contracts::FreshIdentityAllocator;
use gantry::ir::toolchain::BudgetUnit;
use gantry::runtime::BoundedBlockingWorkService;
use gantry::{
    TEST_WORKFLOW_OUTPUT_CEILING_BYTES, TEST_WORKFLOW_TOOLCHAIN_IDENTITY, TestPolicyBound,
    TestWorkflowDeclarations, TestWorkflowIdentity, TestWorkflowPolicy, TestWorkflowReport,
    TestWorkflowRequest, TestWorkflowServices, TestWorkflowStatus, run_test_workflow,
};
use serde_json::{Value, json};

use crate::{
    BLOCKING_WAIT_LIMIT, EXIT_OPERATIONAL_FAILURE, EXIT_SOURCE_INVALID, EXIT_SUCCESS, EXIT_USAGE,
    block_on, published_selection, report_blocking_stall,
};

/// Exact usage line of the `test` command.
const TEST_USAGE: &str =
    "usage: gantry test --max-transitions POSITIVE_INTEGER [--json] [PACKAGE_ROOT]";

/// Declared frontend input bound in bytes.
const TEST_INPUT_BYTES: u64 = 4_194_304;

/// Declared frontend stage bound in stages.
const TEST_FRONTEND_STAGES: u64 = 2;

/// Declared diagnostics bound in diagnostics.
const TEST_DIAGNOSTICS: u64 = 4_096;

/// Fixed blocking-work capacities of the reference CLI.
const TEST_BLOCKING_CAPACITY: u64 = 65_536;

/// One parsed `gantry test` invocation.
struct TestInvocation {
    /// Package directory, defaulting to the current directory.
    package_root: PathBuf,
    /// Declared runtime step bound.
    max_transitions: u64,
    /// Whether the structured report is requested instead of the human marker.
    json: bool,
}

/// Parses one `gantry test` argument list, excluding the `test` token itself.
///
/// Returns `None` after publishing one usage error, so the caller returns the usage exit code
/// without starting any workflow stage.
fn parse(arguments: &[OsString], stderr: &mut dyn Write) -> Option<TestInvocation> {
    let mut max_transitions: Option<u64> = None;
    let mut json = false;
    let mut package_root: Option<PathBuf> = None;
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "--max-transitions" {
            if max_transitions.is_some() {
                return usage_failure(stderr, "duplicate-max-transitions");
            }
            index += 1;
            let Some(value) = arguments.get(index) else {
                return usage_failure(stderr, "missing-max-transitions");
            };
            let Some(parsed) = value
                .to_str()
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|value| *value > 0)
            else {
                return usage_failure(stderr, "max-transitions-must-be-positive-integer");
            };
            max_transitions = Some(parsed);
        } else if argument == "--json" {
            if json {
                return usage_failure(stderr, "duplicate-json");
            }
            json = true;
        } else if argument
            .to_str()
            .is_some_and(|value| value.starts_with('-'))
        {
            return usage_failure(stderr, "unknown-option");
        } else if package_root.is_some() {
            return usage_failure(stderr, "unexpected-argument");
        } else {
            package_root = Some(PathBuf::from(argument));
        }
        index += 1;
    }
    let Some(max_transitions) = max_transitions else {
        return usage_failure(stderr, "missing-max-transitions");
    };
    Some(TestInvocation {
        package_root: package_root.unwrap_or_else(|| PathBuf::from(".")),
        max_transitions,
        json,
    })
}

/// Publishes one usage error and the exact usage line.
fn usage_failure(stderr: &mut dyn Write, code: &str) -> Option<TestInvocation> {
    let _ = writeln!(stderr, "usage-error[{code}]");
    let _ = writeln!(stderr, "{TEST_USAGE}");
    None
}

/// Runs one `gantry test` invocation and returns its process exit code.
pub(crate) fn run(arguments: &[OsString], stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let Some(invocation) = parse(arguments, stderr) else {
        return EXIT_USAGE;
    };
    let Some(policy) = published_policy(invocation.max_transitions, stderr) else {
        return EXIT_OPERATIONAL_FAILURE;
    };
    let selection = published_selection();
    let identity =
        match TestWorkflowIdentity::observed(&selection, TEST_WORKFLOW_TOOLCHAIN_IDENTITY) {
            Ok(identity) => identity,
            Err(error) => {
                let _ = writeln!(stderr, "operational-failure[{}]", error.code());
                return EXIT_OPERATIONAL_FAILURE;
            }
        };
    let allocator = FreshIdentityAllocator::default();
    let identity_source = crate::services::SystemIdentitySource;
    let clock = crate::services::SystemUtcClock;
    let blocking =
        match BoundedBlockingWorkService::new(TEST_BLOCKING_CAPACITY, TEST_BLOCKING_CAPACITY) {
            Ok(blocking) => blocking,
            Err(_) => {
                let _ = writeln!(stderr, "operational-failure[blocking-service-failure]");
                return EXIT_OPERATIONAL_FAILURE;
            }
        };
    let services = TestWorkflowServices {
        allocator: &allocator,
        identity_source: &identity_source,
        clock: &clock,
        blocking: &blocking,
    };
    let request = TestWorkflowRequest {
        package_root: &invocation.package_root,
        protocol_selection: &selection,
        expected_identity: &identity,
        policy: &policy,
        declarations: TestWorkflowDeclarations::unit(),
    };
    let report = match block_on(run_test_workflow(services, request), BLOCKING_WAIT_LIMIT) {
        Ok(report) => report,
        Err(_) => return report_blocking_stall(stderr),
    };
    if !publish(&report, invocation.json, stdout, stderr) {
        return EXIT_OPERATIONAL_FAILURE;
    }
    exit_code(report.status())
}

/// Declares the published workflow policy over the caller's step bound.
fn published_policy(
    maximum_transitions: u64,
    stderr: &mut dyn Write,
) -> Option<TestWorkflowPolicy> {
    let input = TestPolicyBound::new(BudgetUnit::Bytes, TEST_INPUT_BYTES);
    let stages = TestPolicyBound::new(BudgetUnit::Count, TEST_FRONTEND_STAGES);
    let diagnostics = TestPolicyBound::new(BudgetUnit::Count, TEST_DIAGNOSTICS);
    let (Ok(input), Ok(stages), Ok(diagnostics)) = (input, stages, diagnostics) else {
        let _ = writeln!(stderr, "operational-failure[test-policy-invalid]");
        return None;
    };
    match TestWorkflowPolicy::published(input, stages, diagnostics, maximum_transitions) {
        Ok(policy) => Some(policy),
        Err(error) => {
            let _ = writeln!(stderr, "operational-failure[{}]", error.code());
            None
        }
    }
}

/// Publishes one report in the requested format and reports whether publication succeeded.
fn publish(
    report: &TestWorkflowReport,
    json_output: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> bool {
    if json_output {
        return publish_json(report, stdout, stderr);
    }
    publish_human(report, stdout, stderr)
}

/// Publishes exactly one encoded report document, or nothing when it exceeds the ceiling.
fn publish_json(
    report: &TestWorkflowReport,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> bool {
    let Some(bytes) = checked_report_bytes(&report_json(report)) else {
        let _ = writeln!(stderr, "operational-failure[test-report-output-ceiling]");
        return false;
    };
    if stdout.write_all(&bytes).is_err() || stdout.write_all(b"\n").is_err() {
        let _ = writeln!(stderr, "operational-failure[output-failure]");
        return false;
    }
    true
}

/// Encodes one report document when its exact encoded length fits the published ceiling.
fn checked_report_bytes(document: &Value) -> Option<Vec<u8>> {
    let bytes = serde_json::to_vec(document).ok()?;
    (bytes.len() <= TEST_WORKFLOW_OUTPUT_CEILING_BYTES).then_some(bytes)
}

/// Publishes the human marker and its structured detail lines.
fn publish_human(
    report: &TestWorkflowReport,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> bool {
    let marker = match report.status() {
        TestWorkflowStatus::Clean => "test-passed",
        TestWorkflowStatus::TestFailed => "test-failed",
        TestWorkflowStatus::SourceInvalid => "test-source-invalid",
        TestWorkflowStatus::NoTests => "test-no-tests",
        TestWorkflowStatus::Refused => "test-refused",
        TestWorkflowStatus::Exhausted => "test-exhausted",
        TestWorkflowStatus::Cancelled => "test-cancelled",
        TestWorkflowStatus::Operational => "test-operational-failure",
    };
    if writeln!(stdout, "{marker}").is_err() {
        return false;
    }
    if let Some(refusal) = report.refusal() {
        let _ = writeln!(
            stderr,
            "refusal[{}:{}]",
            refusal.stage().wire_name(),
            refusal.code()
        );
    }
    for result in report.results() {
        if let Some(failure) = result.failure() {
            let _ = writeln!(
                stderr,
                "test-failure[{}:{}@{}]",
                failure.code(),
                failure.workflow(),
                site_text(failure.site())
            );
        }
        if let Some(reason) = result.cancellation_reason() {
            let _ = writeln!(stderr, "test-cancelled[{reason}]");
        }
        if let Some(stop) = result.stop() {
            let _ = writeln!(stderr, "test-undriveable[{stop}]");
        }
        if let Some(bound) = result.bound() {
            let _ = writeln!(stderr, "test-exhausted[{bound}]");
        }
    }
    for diagnostic in report.diagnostics() {
        match diagnostic.primary() {
            Some(span) => {
                let _ = writeln!(
                    stderr,
                    "diagnostic[{}:{}] {}:{}..{}",
                    diagnostic.phase(),
                    diagnostic.code(),
                    span.path(),
                    span.start(),
                    span.end()
                );
            }
            None => {
                let _ = writeln!(
                    stderr,
                    "diagnostic[{}:{}]",
                    diagnostic.phase(),
                    diagnostic.code()
                );
            }
        }
    }
    true
}

/// Renders one structural site as dotted components.
fn site_text(site: &[u64]) -> String {
    if site.is_empty() {
        return "-".to_owned();
    }
    site.iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

/// Maps one report judgment to the contract's exit code.
fn exit_code(status: TestWorkflowStatus) -> u8 {
    match status {
        TestWorkflowStatus::Clean => EXIT_SUCCESS,
        TestWorkflowStatus::TestFailed | TestWorkflowStatus::SourceInvalid => EXIT_SOURCE_INVALID,
        TestWorkflowStatus::NoTests
        | TestWorkflowStatus::Refused
        | TestWorkflowStatus::Exhausted
        | TestWorkflowStatus::Cancelled
        | TestWorkflowStatus::Operational => EXIT_OPERATIONAL_FAILURE,
    }
}

/// Encodes the complete versioned report document.
fn report_json(report: &TestWorkflowReport) -> Value {
    json!({
        "format": report.format(),
        "report_version": report.report_version(),
        "status": report.status().wire_name(),
        "identity": report.identity().map(identity_json),
        "expected_identity": identity_json(report.expected_identity()),
        "declared": {
            "registry_inputs": report.declared().registry_inputs(),
            "authority_inputs": report.declared().authority_inputs(),
            "external_artifacts": report.declared().external_artifacts(),
        },
        "policy": policy_json(report.policy()),
        "selection": selection_json(report),
        "package": report.package().map(|package| json!({
            "files": package.files(),
            "bytes": package.bytes(),
        })),
        "inventory": report.inventory().map(|inventory| json!({
            "effects": inventory.effects(),
            "operations": inventory.operations(),
            "live_resources": inventory.live_resources(),
            "authority_ceiling_empty": inventory.authority_ceiling_empty(),
        })),
        "results": report.results().iter().map(result_json).collect::<Vec<_>>(),
        "refusal": report.refusal().map(refusal_json),
        "diagnostics": report.diagnostics().iter().map(diagnostic_json).collect::<Vec<_>>(),
        "arranged_width": report.arranged_width(),
    })
}

/// Encodes the observed identity record.
fn identity_json(identity: &gantry::TestWorkflowIdentity) -> Value {
    let target = identity.target();
    let features = identity.features();
    json!({
        "source_language": version_json(identity.source_language()),
        "specification_revision": identity.specification_revision(),
        "profile_revision": identity.profile_revision(),
        "semantic_mode": identity.semantic_mode().wire_name(),
        "features": {
            "frontend": features.frontend,
            "analyzer": features.analyzer,
            "evaluator": features.evaluator,
            "concurrent": features.concurrent,
            "durable": features.durable,
        },
        "target": {
            "architecture": target.architecture().as_str(),
            "operating_system": target.operating_system().as_str(),
            "abi_environment": target.abi_environment().as_str(),
            "language_edition": target.language_edition(),
            "stdlib_contract": version_json(target.stdlib_contract()),
            "mode": target.mode().wire_name(),
            "digest": target.digest().as_str(),
        },
        "stdlib_contract": version_json(identity.stdlib_contract()),
        "toolchain": identity.toolchain(),
    })
}

/// Encodes the declared policy.
fn policy_json(policy: &TestWorkflowPolicy) -> Value {
    json!({
        "revision": policy.revision(),
        "jobs": policy.jobs(),
        "input": bound_json(policy.input()),
        "stages": bound_json(policy.stages()),
        "diagnostics": bound_json(policy.diagnostics()),
        "maximum_transitions": policy.maximum_transitions(),
        "output_ceiling_bytes": policy.output_ceiling_bytes(),
    })
}

/// Encodes one declared policy bound.
fn bound_json(bound: TestPolicyBound) -> Value {
    json!({
        "unit": bound.unit().wire_name(),
        "limit": bound.limit(),
    })
}

/// Encodes the declared and admitted selection.
fn selection_json(report: &TestWorkflowReport) -> Value {
    let selection = report.selection();
    json!({
        "kind": selection.kind().map(|kind| kind.wire_name()),
        "substitutions": selection
            .substitutions()
            .iter()
            .map(|substitution| substitution.wire_name())
            .collect::<Vec<_>>(),
        "jobs": selection.jobs(),
        "entry": selection.entry(),
    })
}

/// Encodes one ordered target result.
fn result_json(result: &gantry::TestWorkflowTargetResult) -> Value {
    json!({
        "name": result.name(),
        "outcome": result.classification().wire_name(),
        "steps": result.steps(),
        "failure": result.failure().map(|failure| json!({
            "code": failure.code(),
            "workflow": failure.workflow(),
            "site": failure.site(),
        })),
        "cancellation_reason": result.cancellation_reason(),
        "stop": result.stop(),
        "bound": result.bound(),
    })
}

/// Encodes one structured refusal.
fn refusal_json(refusal: &gantry::TestWorkflowRefusal) -> Value {
    json!({
        "stage": refusal.stage().wire_name(),
        "code": refusal.code(),
        "requirement": refusal.requirement(),
        "detail": refusal.detail(),
    })
}

/// Encodes one payload-free diagnostic.
fn diagnostic_json(diagnostic: &gantry::TestWorkflowDiagnostic) -> Value {
    json!({
        "phase": diagnostic.phase(),
        "severity": diagnostic.severity(),
        "category": diagnostic.category(),
        "code": diagnostic.code(),
        "primary": diagnostic.primary().map(|span| json!({
            "path": span.path(),
            "start": span.start(),
            "end": span.end(),
        })),
    })
}

/// Encodes one protocol version.
fn version_json(version: gantry::protocol::ProtocolVersion) -> Value {
    json!({
        "major": version.major,
        "minor": version.minor,
    })
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{TEST_USAGE, checked_report_bytes, exit_code, parse};
    use crate::{EXIT_OPERATIONAL_FAILURE, EXIT_SOURCE_INVALID, EXIT_SUCCESS, EXIT_USAGE, run};
    use gantry::TestWorkflowStatus;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    /// One package directory removed when the test finishes.
    struct TempDirectory(PathBuf);

    impl TempDirectory {
        /// Creates one package directory holding `main.gnt` with the supplied source.
        fn new(source: &[u8]) -> Self {
            let suffix = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("gantry-cli-test-{}-{suffix}", std::process::id()));
            assert!(fs::create_dir(&path).is_ok());
            assert!(fs::write(path.join("main.gnt"), source).is_ok());
            Self(path)
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Builds one argument vector.
    fn arguments(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    /// Runs one `test` invocation against a package.
    fn run_test(package: &TempDirectory, extra: &[&str]) -> (u8, Vec<u8>, Vec<u8>) {
        let mut all = vec![OsString::from("test")];
        all.extend(extra.iter().map(OsString::from));
        all.push(package.0.clone().into_os_string());
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run(&all, &mut stdout, &mut stderr);
        (code, stdout, stderr)
    }

    #[test]
    fn parse_refuses_missing_zero_negative_and_malformed_bounds() {
        let mut stderr = Vec::new();
        assert!(parse(&arguments(&["--max-transitions"]), &mut stderr).is_none());
        assert!(String::from_utf8_lossy(&stderr).contains("missing-max-transitions"));
        for value in ["0", "-1", "invalid", ""] {
            let mut stderr = Vec::new();
            assert!(
                parse(&arguments(&["--max-transitions", value]), &mut stderr).is_none(),
                "declared bound {value:?} must be refused"
            );
            assert!(
                String::from_utf8_lossy(&stderr)
                    .contains("max-transitions-must-be-positive-integer")
            );
        }
        let mut stderr = Vec::new();
        assert!(parse(&arguments(&[]), &mut stderr).is_none());
        assert!(String::from_utf8_lossy(&stderr).contains(TEST_USAGE));
        let mut stderr = Vec::new();
        assert!(
            parse(
                &arguments(&["--max-transitions", "1", "--max-transitions", "2"]),
                &mut stderr
            )
            .is_none()
        );
        let mut stderr = Vec::new();
        assert!(parse(&arguments(&["--unknown"]), &mut stderr).is_none());
        assert!(String::from_utf8_lossy(&stderr).contains("unknown-option"));
        let mut stderr = Vec::new();
        assert!(parse(&arguments(&["--json", "--json"]), &mut stderr).is_none());
        assert!(String::from_utf8_lossy(&stderr).contains("duplicate-json"));
    }

    #[test]
    fn parse_defaults_the_package_root_and_accepts_a_positional_root() {
        let mut stderr = Vec::new();
        let defaulted = parse(&arguments(&["--max-transitions", "7"]), &mut stderr)
            .unwrap_or_else(|| panic!("defaulted root is valid"));
        assert_eq!(defaulted.max_transitions, 7);
        assert_eq!(defaulted.package_root, PathBuf::from("."));
        assert!(!defaulted.json);
        assert!(stderr.is_empty());

        let mut stderr = Vec::new();
        let rooted = parse(
            &arguments(&["--max-transitions", "7", "--json", "pkg"]),
            &mut stderr,
        )
        .unwrap_or_else(|| panic!("positional root is valid"));
        assert!(rooted.json);
        assert_eq!(rooted.package_root, PathBuf::from("pkg"));
    }

    #[test]
    fn exit_codes_follow_the_contract_classes() {
        assert_eq!(exit_code(TestWorkflowStatus::Clean), EXIT_SUCCESS);
        assert_eq!(
            exit_code(TestWorkflowStatus::TestFailed),
            EXIT_SOURCE_INVALID
        );
        assert_eq!(
            exit_code(TestWorkflowStatus::SourceInvalid),
            EXIT_SOURCE_INVALID
        );
        for status in [
            TestWorkflowStatus::NoTests,
            TestWorkflowStatus::Refused,
            TestWorkflowStatus::Exhausted,
            TestWorkflowStatus::Cancelled,
            TestWorkflowStatus::Operational,
        ] {
            assert_eq!(exit_code(status), EXIT_OPERATIONAL_FAILURE);
        }
    }

    #[test]
    fn encoded_reports_over_the_ceiling_are_never_published() {
        let small = serde_json::json!({"report": "small"});
        assert!(checked_report_bytes(&small).is_some());
        let oversized = serde_json::json!({
            "report": "x".repeat(gantry::TEST_WORKFLOW_OUTPUT_CEILING_BYTES + 1),
        });
        assert!(checked_report_bytes(&oversized).is_none());
    }

    #[test]
    fn malformed_usage_exits_sixty_four() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            run(&[OsString::from("test")], &mut stdout, &mut stderr),
            EXIT_USAGE
        );
        assert!(stdout.is_empty());
        assert!(String::from_utf8_lossy(&stderr).contains(TEST_USAGE));
    }

    #[test]
    fn clean_unit_completion_exits_zero() {
        let package = TempDirectory::new(b"fn main() {}");
        let (code, stdout, stderr) = run_test(&package, &["--max-transitions", "100"]);
        assert_eq!(
            code,
            EXIT_SUCCESS,
            "stderr: {}",
            String::from_utf8_lossy(&stderr)
        );
        assert_eq!(stdout, b"test-passed\n");
        assert!(stderr.is_empty());
    }

    #[test]
    fn fixed_test_failure_and_invalid_source_exit_one() {
        let failing = TempDirectory::new(b"fn main() { let value: Int = 1 / 0; discard value; }");
        let (code, stdout, stderr) = run_test(&failing, &["--max-transitions", "100"]);
        assert_eq!(
            code,
            EXIT_SOURCE_INVALID,
            "stderr: {}",
            String::from_utf8_lossy(&stderr)
        );
        assert_eq!(stdout, b"test-failed\n");
        assert!(String::from_utf8_lossy(&stderr).contains("test-failure["));

        let invalid = TempDirectory::new(b"fn main( {");
        let (code, stdout, stderr) = run_test(&invalid, &["--max-transitions", "100"]);
        assert_eq!(code, EXIT_SOURCE_INVALID);
        assert_eq!(stdout, b"test-source-invalid\n");
        assert!(String::from_utf8_lossy(&stderr).contains("diagnostic["));
    }

    #[test]
    fn admission_and_no_tests_and_exhaustion_exit_two() {
        let effects = TempDirectory::new(b"fn main() { discard prompt \"x\" -> String; }");
        let (code, stdout, stderr) = run_test(&effects, &["--max-transitions", "100"]);
        assert_eq!(code, EXIT_OPERATIONAL_FAILURE);
        assert_eq!(stdout, b"test-refused\n");
        assert!(String::from_utf8_lossy(&stderr).contains("refusal[admission:"));

        let value_entry = TempDirectory::new(b"fn main() -> Int { 1 }");
        let (code, stdout, stderr) = run_test(&value_entry, &["--max-transitions", "100"]);
        assert_eq!(
            code,
            EXIT_OPERATIONAL_FAILURE,
            "stderr: {}",
            String::from_utf8_lossy(&stderr)
        );
        assert_eq!(stdout, b"test-no-tests\n");
        assert!(
            String::from_utf8_lossy(&stderr).contains("refusal[admission:no-unit-entry-result]")
        );

        let missing = TempDirectory::new(b"fn helper() {}");
        let (code, stdout, stderr) = run_test(&missing, &["--max-transitions", "100"]);
        assert_eq!(code, EXIT_SOURCE_INVALID);
        assert_eq!(stdout, b"test-source-invalid\n");
        assert!(String::from_utf8_lossy(&stderr).contains("invalid-entry-point"));

        let argv = TempDirectory::new(b"fn main(value: Int) {}");
        let (code, stdout, stderr) = run_test(&argv, &["--max-transitions", "100"]);
        assert_eq!(code, EXIT_OPERATIONAL_FAILURE);
        assert_eq!(stdout, b"test-refused\n");
        assert!(
            String::from_utf8_lossy(&stderr).contains("refusal[admission:argument-taking-entry]"),
            "an argument-taking entry is refused before execution"
        );

        let looping = TempDirectory::new(
            b"fn main() { let mut counter: Int = 0; while counter < 1000000 { counter += 1; } }",
        );
        let (code, stdout, stderr) = run_test(&looping, &["--max-transitions", "20"]);
        assert_eq!(
            code,
            EXIT_OPERATIONAL_FAILURE,
            "stderr: {}",
            String::from_utf8_lossy(&stderr)
        );
        assert_eq!(stdout, b"test-exhausted\n");
    }

    #[test]
    fn json_report_is_bounded_structured_and_never_partial() {
        let package = TempDirectory::new(b"fn main() {}");
        let (code, stdout, stderr) = run_test(&package, &["--max-transitions", "100", "--json"]);
        assert_eq!(
            code,
            EXIT_SUCCESS,
            "stderr: {}",
            String::from_utf8_lossy(&stderr)
        );
        assert!(stderr.is_empty());
        assert!(stdout.len() <= gantry::TEST_WORKFLOW_OUTPUT_CEILING_BYTES + 1);
        let document: serde_json::Value = serde_json::from_slice(&stdout)
            .unwrap_or_else(|error| panic!("report is JSON: {error}"));
        assert_eq!(document["format"], "gantry.test-workflow/v1");
        assert_eq!(document["report_version"], 1);
        assert_eq!(document["status"], "clean");
        assert_eq!(document["selection"]["kind"], "unit");
        assert_eq!(document["selection"]["entry"], "crate::main");
        assert_eq!(document["results"][0]["outcome"], "completed");
        assert_eq!(document["policy"]["maximum_transitions"], 100);
        assert_eq!(document["policy"]["input"]["unit"], "bytes");
        assert_eq!(document["policy"]["stages"]["unit"], "count");
        assert_eq!(document["policy"]["diagnostics"]["unit"], "count");
        assert_eq!(document["inventory"]["effects"], 0);
        assert_eq!(document["inventory"]["operations"], 0);
        assert_eq!(document["inventory"]["live_resources"], 0);
        assert_eq!(document["inventory"]["authority_ceiling_empty"], true);
        assert!(document["refusal"].is_null());
        assert_eq!(document["diagnostics"], serde_json::json!([]));
    }

    #[test]
    fn json_refusal_is_one_structured_document() {
        let effects = TempDirectory::new(b"fn main() { discard prompt \"x\" -> String; }");
        let (code, stdout, stderr) = run_test(&effects, &["--max-transitions", "100", "--json"]);
        assert_eq!(code, EXIT_OPERATIONAL_FAILURE);
        assert!(stderr.is_empty());
        let document: serde_json::Value = serde_json::from_slice(&stdout)
            .unwrap_or_else(|error| panic!("report is JSON: {error}"));
        assert_eq!(document["status"], "refused");
        assert_eq!(document["refusal"]["stage"], "admission");
        assert_eq!(document["refusal"]["code"], "non-empty-effect-inventory");
        assert!(document["results"].as_array().is_some_and(Vec::is_empty));
    }

    /// Replaces the build- and host-bound identity facts with one stable marker.
    fn normalized_report(mut document: serde_json::Value) -> serde_json::Value {
        for record in ["identity", "expected_identity"] {
            document[record]["features"] = serde_json::json!("normalized");
            document[record]["target"] = serde_json::json!("normalized");
            document[record]["specification_revision"] = serde_json::json!("normalized");
            document[record]["profile_revision"] = serde_json::json!("normalized");
        }
        document
    }

    #[test]
    fn clean_json_report_matches_the_published_golden() {
        let package = TempDirectory::new(b"fn main() {}");
        let (code, stdout, stderr) = run_test(&package, &["--max-transitions", "100", "--json"]);
        assert_eq!(
            code,
            EXIT_SUCCESS,
            "stderr: {}",
            String::from_utf8_lossy(&stderr)
        );
        assert!(stderr.is_empty());
        let document: serde_json::Value = serde_json::from_slice(&stdout)
            .unwrap_or_else(|error| panic!("report is JSON: {error}"));

        let expected_identity = gantry::TestWorkflowIdentity::observed(
            &crate::published_selection(),
            gantry::TEST_WORKFLOW_TOOLCHAIN_IDENTITY,
        )
        .unwrap_or_else(|error| panic!("published identity: {}", error.code()));
        let features = gantry::compiled_features();
        assert_eq!(
            document["identity"]["features"]["frontend"],
            serde_json::json!(features.frontend)
        );
        assert_eq!(
            document["identity"]["features"]["analyzer"],
            serde_json::json!(features.analyzer)
        );
        assert_eq!(
            document["identity"]["features"]["evaluator"],
            serde_json::json!(features.evaluator)
        );
        assert_eq!(
            document["identity"]["features"]["concurrent"],
            serde_json::json!(features.concurrent)
        );
        assert_eq!(
            document["identity"]["features"]["durable"],
            serde_json::json!(features.durable)
        );
        assert_eq!(
            document["identity"]["specification_revision"],
            gantry::portable::PORTABLE_SPECIFICATION_REVISION
        );
        assert_eq!(
            document["identity"]["profile_revision"],
            gantry::PROFILE_SPECIFICATION_REVISION
        );
        assert_eq!(
            document["expected_identity"]["toolchain"],
            gantry::TEST_WORKFLOW_TOOLCHAIN_IDENTITY
        );
        assert_eq!(
            document["expected_identity"]["toolchain"],
            document["identity"]["toolchain"]
        );
        let target = expected_identity.target();
        assert_eq!(
            document["identity"]["target"]["architecture"],
            target.architecture().as_str()
        );
        assert_eq!(
            document["identity"]["target"]["operating_system"],
            target.operating_system().as_str()
        );
        assert_eq!(
            document["identity"]["target"]["abi_environment"],
            target.abi_environment().as_str()
        );
        assert_eq!(
            document["identity"]["target"]["language_edition"],
            target.language_edition()
        );
        assert_eq!(
            document["identity"]["target"]["mode"],
            target.mode().wire_name()
        );
        assert_eq!(
            document["identity"]["target"]["digest"],
            target.digest().as_str()
        );

        let golden: serde_json::Value =
            serde_json::from_slice(include_bytes!("../tests/goldens/test-unit-v1.json"))
                .unwrap_or_else(|error| panic!("golden is JSON: {error}"));
        assert_eq!(normalized_report(document), golden);
        assert!(stdout.len() <= gantry::TEST_WORKFLOW_OUTPUT_CEILING_BYTES + 1);
    }
}
