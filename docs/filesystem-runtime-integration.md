# Filesystem runtime integration (first `std.fs` slice)

Status: implementation record for `GNT-GP-FS-001` (`ed0e707c`), delivered under the governing decisions
`governance/issue-resolution-decisions-v1.md` D3, D4, and D10. It is not normative text; `SPEC.md`
Section 47 remains the declaration contract, and `docs/filesystem-support.md` remains the reader
index to what that section declares. This record describes the runtime the repository now contains
and the boundary it deliberately keeps.

## Delivered surface

`gantry-runtime` publishes these items over the declared `std.fs` vocabulary:

- `FsRootDirectory` mounts one declared portable root name onto one pinned host directory
  descriptor, opened with no-follow, directory-only, and close-on-exec flags. It is the only issuer
  of grants: each grant carries the unforgeable identity of that mounted instance, so a grant from
  another instance of the same declared name is refused even though the spelling matches.
- `FsReadOnlyGrant` binds one declared `FsPath` value, the issuing root instance, and one admitted
  `FsTargetMapping`. It answers exactly the declaration-layer grant questions: `create`, `replace`,
  and `remove` are refused as content-mutating actions, `write` and `truncate` are refused as
  content-mutating resource operations, and the operations this slice does not deliver are refused
  as undelivered.
- `FsReadOnlyEndpoint` holds the only live descriptor of one open regular file and implements the
  landed `BoundedIoEndpoint` boundary. It pins descriptor identity, not content. Each open also
  yields an `FsOpenReceipt` naming that exact open instance.
- `close_read_only` requires the issuing grant and the matching receipt. The grant, the receipt,
  and the bound endpoint are inspected before any accounting transition, so a mismatched pair is
  refused with the account still active and physically owned; the descriptor is released exactly
  once and no later call is admitted.
- `FsReadOnlySettlement` is the documented read route. It applies the read-only preflight and the
  grant, receipt, and bound-endpoint association before building the landed settlement service, so
  a write or seek request is refused as a grant refusal, and a foreign grant or endpoint is refused
  as an instance refusal, rather than being dispatched and contained as a host fault.

## Caller shape

1. Mount the declared root: `FsRootDirectory::mount(name, host_directory)`.
2. Admit the declared path value: `FsPath::rooted`, then issue the grant from the mount:
   `root.issue_grant(&path)`.
3. Open the instance: `root.open_read_only(&grant)`, and keep `endpoint.receipt()` alongside it.
4. Bind the endpoint to one admitted Section 28 account whose subject the machine issued, through
   `OwnedHostResource::bind`.
5. Settle each read through `FsReadOnlySettlement::read` with the same receipt, which enforces the
   grant and the instance association before the landed `std.io` settlement service sees the
   request.
6. Close through `close_read_only` with the same grant and receipt.

The grant, the open instance, the owner generation, the operation identity, the resource generation,
and the admission lease are all checked by the types they belong to. A grant is a declaration-layer
value, not a capability: the embedding caller still presents the exact requirement and the machine
owns the occurrence.

## Refusals

`FsRuntimeRefusal` is closed for this slice and distinguishes:

- read-only action denial, read-only operation denial, and undelivered operations;
- an unsupported host target, a grant admitted against another target mapping, and a grant issued by
  another mounted root instance;
- a foreign grant or receipt that does not name the instance being closed;
- a foreign declared root, and a path value the declaration model already refuses;
- a target state that is absent at a position, a refused link at a position, a non-directory, and a
  non-regular file;
- a contained native class, which carries a label only and never a message, a path, or a payload;
- the landed settlement and transport refusals.

No refusal spells a new portable diagnostic. The frozen diagnostics of Section 47 stay exactly
`fs-path-escape` and `fs-path-invalid`, and the link refusal publishes no spelling of its own.

## Resolution, links, and races

The walk starts from the pinned root descriptor and resolves one declared segment at a time. Each
component is classified without following a link and then opened relative to the previous component
descriptor with no-follow, directory-only, and close-on-exec flags. The final object is probed
through an effect-free pinned descriptor first: Linux uses an `O_PATH`-style no-follow descriptor
and macOS uses the event-only open, and in both cases the pinned vnode is type-checked before any
data open. Only a verified regular file is then reopened read-only through the pinned vnode in the
descriptor namespace (`/proc/self/fd` on Linux, `/dev/fd` on macOS), and the reopened descriptor
must carry the same device and inode. A substituted named pipe or device therefore never reaches a
data open or a read. A symbolic link, junction, or reparse point at any position is refused at that
position and is never followed. Replacing an already resolved component cannot redirect the walk,
and a read never re-resolves the declared path value, so one operation performs exactly the one
resolution `GNT-47.8-filesystem-link-policy` declares.

## Targets

Linux and macOS are both delivered, and both are described by one `FsWalkPolicy` value: no-follow
components, directory components, close-on-exec, and one resolution. The lane asserts the two
policies are equal, so neither target has a divergent refusal, progress, or publication rule. Any
other target is `FsHostTarget::Unsupported`, whose policy is absent, so a grant or a mount against
it is refused before a descriptor is opened. Native macOS execution remains a review gap; the
policy equality is a semantic claim, not a native cross-target run.

## Settlement, short reads, and end of stream

One read is one admitted call. The endpoint reports exactly the initialized octets the operating
system returned. Only a read that returned zero octets observes the end of the stream; a positive
short read stays short progress and is never relabelled as end of stream, because the operating
system can return a partial count without the stream being exhausted. The caller observes the end
of stream with one further admitted call, which is a new declared read. No buffer remainder is
carried between calls, no call is retried, and an interrupted call is reported as a contained
native class. The landed settlement service owns the one settlement of the call, including
cancellation and stale-completion containment. A settled call closes its admitted occurrence; a
later call on the same account is refused rather than silently repeated.

## Content immutability

This slice acquires read-only access to one regular file and pins its descriptor identity. It does
not seal the content: another writer can modify or truncate the same inode, and later reads observe
those bytes. The conformance lane records that limitation explicitly instead of claiming a
snapshot. A later immutable snapshot reacquisition would be a fresh authorized open in a new
physical generation, never the reopening of this descriptor, its position, or an accepted lease.

## Durability

The endpoint is unclonable, holds one operating-system descriptor, and implements no serialization
and no logical-value encoding. `encode_resource_reconstruction_record` therefore carries accounting
facts only, and the conformance lane asserts the encoded record contains no declared root or segment
spelling. Recovering those facts never recreates a descriptor.

## Remaining obligations

Still owed to `GNT-GP-FS-001` and deliberately not claimed by this record: `write`, `seek`, `flush`,
`sync`, `truncate`, `lock`, and `watch`; replacement and removal; receipts; short-write prefixes;
poisoning, revocation, and quota refusal paths beyond the landed transport; adapter fault
containment; durable rejection of a live handle beyond the shapes the runtime already refuses; and
the remaining declaration, receipt, and conformance slices of the issue.

## Validation lanes

- `cargo test -p gantry-runtime --all-features fs::` for the runtime lanes: cancellation before
  admission, cancellation during dispatch with withheld octets, a stale completion, a closed
  instance that refuses later calls and is never reopened, and a named pipe refused without
  blocking.
- `cargo test -p gantry-conformance --all-features --test fs_runtime_integration` for the public
  surface: rooted read, short reads and end of stream, read-only denial, predispatch write denial,
  path escape and link refusal, foreign root and foreign receipt refusal, a pinned descriptor
  across a replacement, the recorded content-immutability limitation, a prepared-fixture concurrent
  link swap, durable non-reconstruction, target agreement, and single close.
- The repository floor: generated and workspace checks, the specification audit, formatting, strict
  clippy, the qualification validator, and the full test suite.
