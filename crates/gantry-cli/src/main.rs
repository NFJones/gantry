//! Command-line entry point for Gantry.

use std::ffi::OsString;
use std::io::{self, Write};
use std::process::ExitCode;
#[cfg(feature = "evaluator")]
use std::sync::Arc;

#[cfg(feature = "frontend")]
use std::future::Future;
#[cfg(feature = "frontend")]
use std::pin::pin;
#[cfg(feature = "frontend")]
use std::task::{Context, Poll, Waker};

#[cfg(feature = "frontend")]
use gantry::diagnostic::{DiagnosticRenderOptions, render_diagnostic};
#[cfg(feature = "frontend")]
use gantry::frontend::PackageSyntaxStatus;
#[cfg(feature = "frontend")]
use gantry::host::contracts::FreshIdentityAllocator;
#[cfg(feature = "frontend")]
use gantry::portable::{PORTABLE_SPECIFICATION_REVISION, PROTOCOL_FAMILY_DEFINITIONS};
#[cfg(feature = "frontend")]
use gantry::protocol::{ProtocolSelection, ProtocolVersion, SelectedProtocol};
#[cfg(feature = "evaluator")]
use gantry::runtime::{InterpreterConfiguration, MachineOutcome, RequiredConfiguration};
#[cfg(feature = "frontend")]
use gantry::source::FrontendLimits;
#[cfg(feature = "evaluator")]
use gantry::value::DEFAULT_VALUE_LIMITS;
#[cfg(feature = "analyzer")]
use gantry::{AnalyzePackageCoordinator, AnalyzePackageRequest, AnalyzePackageStatus};
#[cfg(feature = "evaluator")]
use gantry::{Interpreter, StartExecutionRequest, StartExecutionResult};
#[cfg(feature = "frontend")]
use gantry::{ValidatePackageCoordinator, ValidatePackageRequest};
#[cfg(feature = "evaluator")]
use gantry_adapter_tokio::TokioExecutor;

mod services;

const EXIT_SUCCESS: u8 = 0;
const EXIT_SOURCE_INVALID: u8 = 1;
const EXIT_OPERATIONAL_FAILURE: u8 = 2;
const EXIT_USAGE: u8 = 64;

/// Starts the Gantry command-line application.
fn main() -> ExitCode {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    ExitCode::from(run(&arguments, &mut stdout, &mut stderr))
}

fn run(arguments: &[OsString], stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    match arguments {
        [] => write_line(
            stdout,
            "gantry: agent-control language for Mezzanine",
            stderr,
        ),
        [command] if command == "check" => check_command(std::path::Path::new("."), stdout, stderr),
        [command, package_root] if command == "check" => {
            check_command(std::path::Path::new(package_root), stdout, stderr)
        }
        [command] if command == "analyze" => {
            analyze_command(std::path::Path::new("."), stdout, stderr)
        }
        [command, package_root] if command == "analyze" => {
            analyze_command(std::path::Path::new(package_root), stdout, stderr)
        }
        [command] if command == "run" => run_command(std::path::Path::new("."), stdout, stderr),
        [command, package_root] if command == "run" => {
            run_command(std::path::Path::new(package_root), stdout, stderr)
        }
        _ => {
            let _ = writeln!(stderr, "usage: gantry (check|analyze|run) [PACKAGE_ROOT]");
            EXIT_USAGE
        }
    }
}

fn write_line(stdout: &mut dyn Write, line: &str, stderr: &mut dyn Write) -> u8 {
    if writeln!(stdout, "{line}").is_ok() {
        EXIT_SUCCESS
    } else {
        let _ = writeln!(stderr, "operational-failure[output-failure]");
        EXIT_OPERATIONAL_FAILURE
    }
}

#[cfg(feature = "frontend")]
fn check_command(
    package_root: &std::path::Path,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    let selection = published_selection();
    let limits = FrontendLimits::new(
        4_096,
        16_777_216,
        268_435_456,
        4_194_304,
        4_096,
        268_435_456,
        268_435_456,
        268_435_456,
        268_435_456,
    )
    .unwrap_or_else(|_| unreachable!("fixed CLI limits are valid"));
    let allocator = FreshIdentityAllocator::default();
    let identity_source = services::SystemIdentitySource;
    let clock = services::SystemUtcClock;
    let coordinator = ValidatePackageCoordinator::new(&allocator, &identity_source, &clock);
    let result = block_on(coordinator.validate(ValidatePackageRequest {
        package_root,
        protocol_selection: &selection,
        frontend_limits: limits,
        event_delivery: None,
    }));
    match result {
        Ok(result) if result.phase.status() == PackageSyntaxStatus::Valid => {
            write_line(stdout, "syntax-valid", stderr)
        }
        Ok(result) => {
            for diagnostic in result.phase.diagnostics() {
                match render_diagnostic(
                    diagnostic,
                    result.phase.snapshot(),
                    DiagnosticRenderOptions::default(),
                ) {
                    Ok(rendered) => {
                        if write!(stderr, "{}", rendered.text).is_err() {
                            return EXIT_OPERATIONAL_FAILURE;
                        }
                    }
                    Err(_) => {
                        let _ = writeln!(stderr, "operational-failure[diagnostic-render-failure]");
                        return EXIT_OPERATIONAL_FAILURE;
                    }
                }
            }
            if writeln!(stdout, "syntax-invalid").is_err() {
                return EXIT_OPERATIONAL_FAILURE;
            }
            EXIT_SOURCE_INVALID
        }
        Err(error) => {
            let _ = writeln!(stderr, "operational-failure[{}]", error.code());
            EXIT_OPERATIONAL_FAILURE
        }
    }
}

#[cfg(not(feature = "frontend"))]
fn check_command(
    _package_root: &std::path::Path,
    _stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    let _ = writeln!(stderr, "operational-failure[frontend-unavailable]");
    EXIT_OPERATIONAL_FAILURE
}

#[cfg(feature = "analyzer")]
fn analyze_command(
    package_root: &std::path::Path,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    let selection = published_selection();
    let limits = FrontendLimits::new(
        4_096,
        16_777_216,
        268_435_456,
        4_194_304,
        4_096,
        268_435_456,
        268_435_456,
        268_435_456,
        268_435_456,
    )
    .unwrap_or_else(|_| unreachable!("fixed CLI limits are valid"));
    let allocator = FreshIdentityAllocator::default();
    let identity_source = services::SystemIdentitySource;
    let clock = services::SystemUtcClock;
    let coordinator = AnalyzePackageCoordinator::new(&allocator, &identity_source, &clock);
    let result = block_on(coordinator.analyze(AnalyzePackageRequest {
        package_root,
        protocol_selection: &selection,
        frontend_limits: limits,
        event_delivery: None,
    }));
    match result {
        Ok(result) => {
            let diagnostics = result.analysis.as_ref().map_or_else(
                || result.syntax.diagnostics(),
                |analysis| analysis.diagnostics(),
            );
            for diagnostic in diagnostics {
                match render_diagnostic(
                    diagnostic,
                    result.syntax.snapshot(),
                    DiagnosticRenderOptions::default(),
                ) {
                    Ok(rendered) => {
                        if write!(stderr, "{}", rendered.text).is_err() {
                            return EXIT_OPERATIONAL_FAILURE;
                        }
                    }
                    Err(_) => {
                        let _ = writeln!(stderr, "operational-failure[diagnostic-render-failure]");
                        return EXIT_OPERATIONAL_FAILURE;
                    }
                }
            }
            if writeln!(stdout, "{}", result.status.wire_name()).is_err() {
                return EXIT_OPERATIONAL_FAILURE;
            }
            if result.status == AnalyzePackageStatus::SourceValid {
                EXIT_SUCCESS
            } else {
                EXIT_SOURCE_INVALID
            }
        }
        Err(error) => {
            let _ = writeln!(stderr, "operational-failure[{}]", error.code());
            EXIT_OPERATIONAL_FAILURE
        }
    }
}

#[cfg(not(feature = "analyzer"))]
fn analyze_command(
    _package_root: &std::path::Path,
    _stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    let _ = writeln!(stderr, "operational-failure[analyzer-unavailable]");
    EXIT_OPERATIONAL_FAILURE
}

#[cfg(feature = "evaluator")]
fn run_command(
    package_root: &std::path::Path,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            let _ = writeln!(stderr, "operational-failure[executor-failure]");
            return EXIT_OPERATIONAL_FAILURE;
        }
    };
    let integration = Arc::new(services::CliIntegration);
    let identity_source = Arc::new(services::SystemIdentitySource);
    let jitter = Arc::new(services::SystemJitterSource);
    let executor = Arc::new(TokioExecutor::new(runtime.handle().clone(), jitter));
    let required = RequiredConfiguration::new(
        cli_frontend_limits(),
        1_048_576,
        1_048_576,
        DEFAULT_VALUE_LIMITS,
        1_000_000,
        100_000,
        100_000,
        1_000,
    )
    .unwrap_or_else(|_| unreachable!("fixed CLI evaluator limits are valid"));
    let configuration = InterpreterConfiguration::new(executor, identity_source, required);
    let interpreter = Interpreter::new(
        configuration,
        Arc::new(services::SystemUtcClock),
        integration.clone(),
        integration,
    );
    let selection = published_selection();
    let started = runtime.block_on(interpreter.start_execution(StartExecutionRequest {
        package_root,
        protocol_selection: &selection,
        required_peers: &[],
        entry_input: None,
        root_session: None,
        event_delivery: None,
    }));
    let accepted = match started {
        StartExecutionResult::Accepted(accepted) => accepted,
        StartExecutionResult::Rejected(failure) => {
            render_start_diagnostics(&failure, stderr);
            let _ = writeln!(
                stderr,
                "start-rejected[{}:{}]",
                failure.category.wire_name(),
                failure.code
            );
            return if matches!(
                failure.category,
                gantry::portable::StartFailureCategory::Syntax
                    | gantry::portable::StartFailureCategory::Analysis
            ) {
                EXIT_SOURCE_INVALID
            } else {
                EXIT_OPERATIONAL_FAILURE
            };
        }
    };
    let snapshot = match runtime.block_on(interpreter.run_execution(*accepted)) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            let _ = writeln!(stderr, "operational-failure[run-execution:{error:?}]");
            let _ = runtime.block_on(interpreter.shutdown());
            return EXIT_OPERATIONAL_FAILURE;
        }
    };
    let outcome = snapshot
        .foreground
        .as_ref()
        .unwrap_or_else(|| unreachable!("completed run fixes foreground outcome"));
    let code = match outcome {
        MachineOutcome::Succeeded(value) => {
            if stdout.write_all(value.canonical_json().bytes()).is_err()
                || writeln!(stdout).is_err()
            {
                EXIT_OPERATIONAL_FAILURE
            } else {
                EXIT_SUCCESS
            }
        }
        MachineOutcome::Failed(failure) => {
            let _ = writeln!(stderr, "runtime-failure[{}]", failure.code.wire_name());
            EXIT_OPERATIONAL_FAILURE
        }
        MachineOutcome::Cancelled(reason) => {
            let _ = writeln!(stderr, "runtime-cancelled[{reason}]");
            EXIT_OPERATIONAL_FAILURE
        }
    };
    if runtime.block_on(interpreter.shutdown()).is_err() {
        return EXIT_OPERATIONAL_FAILURE;
    }
    code
}

#[cfg(not(feature = "evaluator"))]
fn run_command(
    _package_root: &std::path::Path,
    _stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    let _ = writeln!(stderr, "operational-failure[evaluator-unavailable]");
    EXIT_OPERATIONAL_FAILURE
}

#[cfg(feature = "evaluator")]
fn render_start_diagnostics(failure: &gantry::StartExecutionFailure, stderr: &mut dyn Write) {
    let Some(activity) = &failure.package_activity else {
        return;
    };
    let diagnostics = activity.analysis.as_ref().map_or_else(
        || activity.syntax.diagnostics(),
        |analysis| analysis.diagnostics(),
    );
    for diagnostic in diagnostics {
        if let Ok(rendered) = render_diagnostic(
            diagnostic,
            activity.syntax.snapshot(),
            DiagnosticRenderOptions::default(),
        ) {
            let _ = write!(stderr, "{}", rendered.text);
        }
    }
}

#[cfg(feature = "frontend")]
fn cli_frontend_limits() -> FrontendLimits {
    FrontendLimits::new(
        4_096,
        16_777_216,
        268_435_456,
        4_194_304,
        4_096,
        268_435_456,
        268_435_456,
        268_435_456,
        268_435_456,
    )
    .unwrap_or_else(|_| unreachable!("fixed CLI limits are valid"))
}

#[cfg(feature = "frontend")]
fn published_selection() -> ProtocolSelection {
    ProtocolSelection::new(
        PORTABLE_SPECIFICATION_REVISION,
        PROTOCOL_FAMILY_DEFINITIONS
            .iter()
            .map(|definition| SelectedProtocol {
                family: definition.family,
                version: ProtocolVersion {
                    major: definition.major,
                    minor: definition.minor,
                },
            })
            .collect(),
    )
    .unwrap_or_else(|_| unreachable!("generated protocol selection is supported"))
}

#[cfg(feature = "frontend")]
fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = pin!(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use gantry::diagnostic::{DiagnosticRenderOptions, render_diagnostic};
    use gantry::portable::{DiagnosticCategory, DiagnosticSeverity};
    use gantry::source::{
        ByteSpan, DiagnosticCode, DiagnosticMetadata, DiagnosticPhase, SourceLimits,
        SourceSnapshotBuilder, SourceSpan, StructuredDiagnostic,
    };

    use super::{EXIT_OPERATIONAL_FAILURE, EXIT_SOURCE_INVALID, EXIT_SUCCESS, EXIT_USAGE, run};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempDirectory(PathBuf);

    impl TempDirectory {
        fn new(source: &[u8]) -> Self {
            let suffix = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("gantry-cli-check-{}-{suffix}", std::process::id()));
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

    #[test]
    fn cli_composition_defaults_to_source_redaction() {
        let limits = SourceLimits::new(1, 32, 32, 1, 1);
        assert!(limits.is_ok());
        let mut builder =
            SourceSnapshotBuilder::new(limits.unwrap_or_else(|_| unreachable!("checked above")));
        let source_id = builder.add_file("main.gnt", b"SECRET");
        assert!(source_id.is_ok());
        let snapshot = builder.finish();
        let source = snapshot.get(&source_id.unwrap_or_else(|_| unreachable!("checked above")));
        assert!(source.is_some());
        let primary = SourceSpan::new(
            source.unwrap_or_else(|| unreachable!("checked above")),
            ByteSpan::new(0, 6).unwrap_or_else(|_| unreachable!("ordered span")),
        );
        assert!(primary.is_ok());
        let diagnostic = StructuredDiagnostic::new(
            DiagnosticMetadata {
                phase: DiagnosticPhase::Syntax,
                severity: DiagnosticSeverity::Error,
                category: DiagnosticCategory::Syntax,
                code: DiagnosticCode::new("unexpected-token")
                    .unwrap_or_else(|_| unreachable!("valid code")),
            },
            "unexpected token",
            Some(primary.unwrap_or_else(|_| unreachable!("checked above"))),
            Vec::new(),
            BTreeMap::new(),
        );
        assert!(diagnostic.is_ok());
        let rendered = render_diagnostic(
            &diagnostic.unwrap_or_else(|_| unreachable!("checked above")),
            &snapshot,
            DiagnosticRenderOptions::default(),
        );
        assert!(rendered.is_ok());
        assert!(
            !rendered
                .unwrap_or_else(|_| unreachable!("checked above"))
                .text
                .contains("SECRET")
        );
    }

    #[cfg(feature = "frontend")]
    #[test]
    fn check_command_maps_valid_invalid_operational_and_usage_results() {
        let valid = TempDirectory::new(b"fn main() {}");
        let invalid = TempDirectory::new(b"fn SECRET( {");

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            run(
                &[OsString::from("check"), valid.0.clone().into_os_string()],
                &mut stdout,
                &mut stderr,
            ),
            EXIT_SUCCESS
        );
        assert_eq!(stdout, b"syntax-valid\n");
        assert!(stderr.is_empty());

        stdout.clear();
        stderr.clear();
        assert_eq!(
            run(
                &[OsString::from("check"), invalid.0.clone().into_os_string()],
                &mut stdout,
                &mut stderr,
            ),
            EXIT_SOURCE_INVALID
        );
        assert_eq!(stdout, b"syntax-invalid\n");
        assert!(!String::from_utf8_lossy(&stderr).contains("SECRET"));

        stdout.clear();
        stderr.clear();
        assert_eq!(
            run(
                &[
                    OsString::from("check"),
                    std::env::temp_dir()
                        .join("gantry-missing-package-root")
                        .into_os_string(),
                ],
                &mut stdout,
                &mut stderr,
            ),
            EXIT_OPERATIONAL_FAILURE
        );
        assert!(String::from_utf8_lossy(&stderr).contains("operational-failure"));

        stdout.clear();
        stderr.clear();
        assert_eq!(
            run(&[OsString::from("unknown")], &mut stdout, &mut stderr),
            EXIT_USAGE
        );
        assert!(String::from_utf8_lossy(&stderr).contains("usage: gantry (check|analyze|run)"));
    }

    #[cfg(feature = "analyzer")]
    #[test]
    fn analyze_command_maps_source_valid_and_invalid_results() {
        let valid = TempDirectory::new(b"fn main() {}");
        let invalid = TempDirectory::new(b"fn main() -> Int { \"wrong\" }");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        assert_eq!(
            run(
                &[OsString::from("analyze"), valid.0.clone().into_os_string()],
                &mut stdout,
                &mut stderr,
            ),
            EXIT_SUCCESS
        );
        assert_eq!(stdout, b"source-valid\n");
        assert!(stderr.is_empty());

        stdout.clear();
        stderr.clear();
        assert_eq!(
            run(
                &[
                    OsString::from("analyze"),
                    invalid.0.clone().into_os_string(),
                ],
                &mut stdout,
                &mut stderr,
            ),
            EXIT_SOURCE_INVALID
        );
        assert_eq!(stdout, b"source-invalid\n");
        assert!(String::from_utf8_lossy(&stderr).contains("type"));
    }

    #[cfg(feature = "evaluator")]
    #[test]
    fn run_command_maps_success_source_rejection_and_usage() {
        let valid = TempDirectory::new(b"fn main() -> Int { 1 + 2 }");
        let invalid = TempDirectory::new(b"fn main() -> Int { \"SECRET\" }");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        assert_eq!(
            run(
                &[OsString::from("run"), valid.0.clone().into_os_string()],
                &mut stdout,
                &mut stderr,
            ),
            EXIT_SUCCESS
        );
        assert_eq!(stdout, b"3\n");
        assert!(stderr.is_empty());

        stdout.clear();
        stderr.clear();
        assert_eq!(
            run(
                &[OsString::from("run"), invalid.0.clone().into_os_string()],
                &mut stdout,
                &mut stderr,
            ),
            EXIT_SOURCE_INVALID
        );
        assert!(stdout.is_empty());
        assert!(String::from_utf8_lossy(&stderr).contains("start-rejected[analysis:"));
        assert!(!String::from_utf8_lossy(&stderr).contains("SECRET"));
    }
}
