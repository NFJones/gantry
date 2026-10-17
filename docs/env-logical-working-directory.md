# Portable logical working directories

This note describes the pure logical working-directory model in
`crates/gantry-ir/src/env_cwd.rs`. It implements the data-only rules already
stated by `GNT-30.2-bounded-launch-snapshot-and-capability-closure` and
`GNT-30.3-arguments-environment-and-logical-cwd`, within the intended domain of
`GNT-49.0-environment-foundation-scope`. It publishes no new requirement row and
no new `std.env` module or item row.

The model publishes rooted portable logical working-directory values: an exact
logical root plus ordered retained segments. It is not a directory handle, a
filesystem capability, an adapter, a launcher, or a host path. It reads no
ambient process state, performs no host I/O, and carries no authority: path
text is data only.

## Rooted values and bounded admission

A logical root is a portable name: an ASCII lowercase letter followed by ASCII
lowercase letters, digits, or `_`. A root names a logical scope, never a host
root, drive, share, or home directory. A segment is nonempty exact UTF-8 text
without a separator, drive or stream marker, NUL, or control scalar, and it is
never `.` or `..`.

`CwdLimits` declares three finite, nonzero bounds: canonical path bytes, retained
segment count, and root or segment bytes. The declared defaults are
`CWD_DEFAULT_MAX_PATH_BYTES`, `CWD_DEFAULT_MAX_SEGMENTS`, and
`CWD_DEFAULT_MAX_SEGMENT_BYTES`. The presented text byte bound is checked before
the text is split, so an oversized presentation is refused before component
work.

## Normalization and composition

Explicit root and relative composition always returns a new value. A presented
text beginning with `/` composes from the declared root; any other text composes
from the current retained segments. Empty and `.` components are dropped, every
`..` removes one retained segment, and normalization refuses escape when a `..`
would leave the declared root. An admitted value is therefore already
normalized and spells `root/segment/...` exactly.

## Target encoding and case policy

Target encoding and case policy is explicit declared data, never an ambient host
or locale observation. A value is always exact UTF-8 data and is never folded
during admission or equality. `CwdEncodingPolicy` declares `utf8` or `ascii`,
`CwdCasePolicy` declares `sensitive` or `ascii-insensitive`, and
`CWD_TARGET_POLICIES` publishes the four closed combinations. `admit_under`
refuses a value that a selected ASCII encoding cannot represent, and
`compare_under` applies only the declared ASCII uppercase fold; non-ASCII
scalars stay exact. Equality of values is exact over the root and segments, and
admission bounds are not part of value identity.

## No native conversion and no authority

There is no implicit native or text conversion. A native separator, drive
marker, stream marker, or doubled leading separator is refused rather than
translated, a non-UTF-8 presentation is refused rather than reinterpreted, and
`~` or `$NAME` stays literal data rather than expanding. The canonical text
carries no directory authority, and no operation consults a host current
directory, environment, locale, case rule, or filesystem namespace.

## Evidence and boundaries

`crates/gantry-conformance/tests/env_logical_cwd.rs` covers rooted admission,
explicit composition, normalization and escape refusal, exact path, segment, and
count bounds, explicit encoding and ASCII case policy, native-form refusal, and
the data-only boundary. That lane performs no host I/O.

The model declares no directory handle, capability grant, adapter, host trait,
launcher, ambient read or write, path authority, or runtime availability.
Native directory handles and physical host mapping remain outside this slice
because they require the source-resource carrier and a reviewed authority and
host mapping. Passing this lane does not qualify a specification revision,
release, target adapter, or runtime.
