//! Private system services for the supported CLI composition.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use gantry::host::contracts::{
    EmbeddingVersion, HookFactory, HostError, HostFuture, HostRequest, HostResponse,
    IdentitySource, InclusiveJitterRange, IntegrationPreflight, JitterSource, OperationHook,
    UtcClock,
};
use gantry::host::embedding::EmbeddingOperation;
use gantry::portable::IdentityKind;
use gantry::timestamp::UtcTimestamp;

/// CLI-private cryptographic-random identity source.
pub(crate) struct SystemIdentitySource;

impl IdentitySource for SystemIdentitySource {
    fn fresh_material(&self, _: IdentityKind) -> Result<[u8; 32], HostError> {
        fill_identity_material(getrandom::fill)
    }
}

/// CLI-private system UTC clock.
pub(crate) struct SystemUtcClock;

impl UtcClock for SystemUtcClock {
    fn utc_now<'a>(&'a self) -> HostFuture<'a, Result<UtcTimestamp, HostError>> {
        Box::pin(async { timestamp_from_system_time(SystemTime::now()) })
    }
}

/// CLI-private unbiased operating-system jitter source.
#[allow(
    dead_code,
    reason = "the evaluator CLI composition that selects this source is owned by GNT-CLI-001"
)]
pub(crate) struct SystemJitterSource;

impl JitterSource for SystemJitterSource {
    fn sample_inclusive(&self, range: InclusiveJitterRange) -> Result<u64, HostError> {
        sample_inclusive_with(range, getrandom::fill)
    }
}

/// CLI-private integration used for preflight and deterministic packages.
pub(crate) struct CliIntegration;

impl IntegrationPreflight for CliIntegration {
    fn call<'a>(&'a self, request: HostRequest) -> HostFuture<'a, Result<HostResponse, HostError>> {
        let operation = request.operation();
        let response = match operation {
            EmbeddingOperation::ResolveMappings => {
                let bytes = request.canonical_bytes();
                let actions = !contains(bytes, b"\"action_signatures\":[]");
                let agents = !contains(bytes, b"\"agent_names\":[]");
                match (actions, agents) {
                    (true, true) => b"{\"action_mapping_revision\":\"cli-actions-v1\",\"agent_mapping_revision\":\"cli-agents-v1\",\"result\":\"resolved\"}".as_slice(),
                    (true, false) => b"{\"action_mapping_revision\":\"cli-actions-v1\",\"result\":\"resolved\"}".as_slice(),
                    (false, true) => b"{\"agent_mapping_revision\":\"cli-agents-v1\",\"result\":\"resolved\"}".as_slice(),
                    (false, false) => b"{\"result\":\"resolved\"}".as_slice(),
                }
            }
            EmbeddingOperation::ResolveSessions => b"{\"result\":\"resolved\"}",
            EmbeddingOperation::EstablishSession => b"{\"result\":\"established\"}",
            _ => {
                return Box::pin(async {
                    Err(integration_failure("unsupported-preflight-operation"))
                });
            }
        };
        Box::pin(async move {
            HostResponse::new(EmbeddingVersion::V1, operation, Arc::from(response))
                .map_err(|_| integration_failure("invalid-cli-response"))
        })
    }
}

impl HookFactory for CliIntegration {
    fn create_hook<'a>(
        &'a self,
        _request: HostRequest,
    ) -> HostFuture<'a, Result<Box<dyn OperationHook>, HostError>> {
        Box::pin(async { Err(integration_failure("cli-hook-unconfigured")) })
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn integration_failure(code: &'static str) -> HostError {
    HostError {
        code: Arc::from(code),
        protected_diagnostic: None,
    }
}

fn fill_identity_material<E>(
    fill: impl FnOnce(&mut [u8]) -> Result<(), E>,
) -> Result<[u8; 32], HostError> {
    let mut material = [0_u8; 32];
    fill(&mut material).map_err(|_| HostError {
        code: Arc::from("identity-source-failure"),
        protected_diagnostic: None,
    })?;
    Ok(material)
}

#[allow(
    dead_code,
    reason = "the evaluator CLI composition that calls this helper is owned by GNT-CLI-001"
)]
fn sample_inclusive_with<E>(
    range: InclusiveJitterRange,
    mut fill: impl FnMut(&mut [u8]) -> Result<(), E>,
) -> Result<u64, HostError> {
    let width = range.maximum() - range.minimum() + 1;
    if width == 1 {
        return Ok(range.minimum());
    }
    let acceptance_bound = u64::MAX - (u64::MAX % width);
    loop {
        let mut bytes = [0_u8; 8];
        fill(&mut bytes).map_err(|_| jitter_failure())?;
        let sample = u64::from_ne_bytes(bytes);
        if sample < acceptance_bound {
            return Ok(range.minimum() + sample % width);
        }
    }
}

fn timestamp_from_system_time(now: SystemTime) -> Result<UtcTimestamp, HostError> {
    let (seconds, microseconds) = match now.duration_since(UNIX_EPOCH) {
        Ok(duration) => (
            i64::try_from(duration.as_secs()).map_err(|_| clock_failure())?,
            duration.subsec_micros(),
        ),
        Err(error) => {
            let duration = error.duration();
            let whole_seconds = i64::try_from(duration.as_secs()).map_err(|_| clock_failure())?;
            let fractional_microseconds = duration.subsec_micros();
            if fractional_microseconds == 0 {
                (-whole_seconds, 0)
            } else {
                (
                    whole_seconds
                        .checked_add(1)
                        .and_then(|value| value.checked_neg())
                        .ok_or_else(clock_failure)?,
                    1_000_000 - fractional_microseconds,
                )
            }
        }
    };
    UtcTimestamp::from_unix_seconds(seconds, microseconds).map_err(|_| clock_failure())
}

fn clock_failure() -> HostError {
    HostError {
        code: Arc::from("executor-failure"),
        protected_diagnostic: None,
    }
}

#[allow(
    dead_code,
    reason = "the evaluator CLI composition that calls this helper is owned by GNT-CLI-001"
)]
fn jitter_failure() -> HostError {
    HostError {
        code: Arc::from("executor-failure"),
        protected_diagnostic: None,
    }
}

#[cfg(test)]
mod tests {
    use std::process::Command;
    use std::time::Duration;

    use gantry::host::contracts::{IdentitySource, InclusiveJitterRange, JitterSource};
    use gantry::portable::IdentityKind;

    use super::{
        SystemIdentitySource, SystemJitterSource, fill_identity_material, sample_inclusive_with,
        timestamp_from_system_time,
    };
    use std::time::UNIX_EPOCH;

    #[test]
    fn fills_all_identity_material_without_fallback() {
        let material = fill_identity_material(|buffer| {
            assert_eq!(buffer.len(), 32);
            for (index, byte) in buffer.iter_mut().enumerate() {
                *byte = u8::try_from(index).unwrap_or_default();
            }
            Ok::<(), ()>(())
        });
        assert_eq!(material, Ok(std::array::from_fn(|index| index as u8)));
    }

    #[test]
    fn system_time_is_checked_and_truncated_to_microseconds() {
        let timestamp =
            timestamp_from_system_time(UNIX_EPOCH + Duration::new(951_827_696, 123_456_789));
        assert_eq!(
            timestamp.map(|value| value.to_string()),
            Ok("2000-02-29T12:34:56.123456Z".to_owned())
        );
        assert_eq!(
            timestamp_from_system_time(UNIX_EPOCH - Duration::new(1, 500_000_001))
                .map(|value| value.to_string()),
            Ok("1969-12-31T23:59:58.500000Z".to_owned())
        );
        assert_eq!(
            timestamp_from_system_time(UNIX_EPOCH - Duration::from_nanos(1))
                .map(|value| value.to_string()),
            Ok("1970-01-01T00:00:00.000000Z".to_owned())
        );
    }

    #[test]
    fn random_failure_has_no_fallback_material() {
        let result = fill_identity_material(|_| Err(()));
        assert!(result.is_err());
        assert_eq!(
            result.err().map(|error| error.code),
            Some("identity-source-failure".into())
        );
    }

    #[test]
    fn jitter_sampling_is_inclusive_unbiased_and_failure_preserving() {
        let range = InclusiveJitterRange::new(2, 7)
            .unwrap_or_else(|| unreachable!("fixture range is valid"));
        let minimum = sample_inclusive_with(range, |buffer| {
            buffer.copy_from_slice(&0_u64.to_ne_bytes());
            Ok::<(), ()>(())
        });
        assert_eq!(minimum, Ok(2));
        let maximum = sample_inclusive_with(range, |buffer| {
            buffer.copy_from_slice(&5_u64.to_ne_bytes());
            Ok::<(), ()>(())
        });
        assert_eq!(maximum, Ok(7));

        let mut calls = 0_u8;
        let after_rejection = sample_inclusive_with(range, |buffer| {
            let value = if calls == 0 { u64::MAX } else { 1 };
            calls = calls.saturating_add(1);
            buffer.copy_from_slice(&value.to_ne_bytes());
            Ok::<(), ()>(())
        });
        assert_eq!(after_rejection, Ok(3));
        assert_eq!(calls, 2);

        let failure = sample_inclusive_with(range, |_| Err(()));
        assert_eq!(
            failure.err().map(|error| error.code),
            Some("executor-failure".into())
        );

        let singleton = InclusiveJitterRange::new(9, 9)
            .unwrap_or_else(|| unreachable!("singleton range is valid"));
        assert_eq!(SystemJitterSource.sample_inclusive(singleton), Ok(9));
    }

    #[test]
    fn child_process_emits_random_identity() {
        if std::env::var_os("GANTRY_IDENTITY_CHILD").is_none() {
            return;
        }
        let material = SystemIdentitySource.fresh_material(IdentityKind::Activity);
        assert!(material.is_ok());
        let material = material.unwrap_or_else(|_| unreachable!("checked above"));
        let hexadecimal = material
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        println!("GANTRY_IDENTITY={hexadecimal}");
    }

    #[test]
    fn os_random_source_does_not_repeat_across_process_restarts() {
        fn run_child() -> String {
            let executable = std::env::current_exe();
            assert!(executable.is_ok());
            let output = executable.and_then(|executable| {
                Command::new(executable)
                    .args([
                        "--exact",
                        "services::tests::child_process_emits_random_identity",
                        "--nocapture",
                    ])
                    .env("GANTRY_IDENTITY_CHILD", "1")
                    .output()
            });
            assert!(output.is_ok());
            let output = output.unwrap_or_else(|_| unreachable!("checked above"));
            assert!(output.status.success());
            let stdout = String::from_utf8(output.stdout);
            assert!(stdout.is_ok());
            stdout
                .unwrap_or_default()
                .lines()
                .find_map(|line| line.strip_prefix("GANTRY_IDENTITY="))
                .map(str::to_owned)
                .unwrap_or_else(|| panic!("child process omitted identity material"))
        }

        let first = run_child();
        let second = run_child();
        assert_eq!(first.len(), 64);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(first, second);
    }
}
