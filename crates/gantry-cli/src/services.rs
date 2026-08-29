//! Private system services for the supported CLI composition.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use gantry::host::contracts::{HostError, HostFuture, IdentitySource, UtcClock};
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

#[cfg(test)]
mod tests {
    use std::process::Command;
    use std::time::Duration;

    use gantry::host::contracts::IdentitySource;
    use gantry::portable::IdentityKind;

    use super::{SystemIdentitySource, fill_identity_material, timestamp_from_system_time};
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
