# Application-native directory contract

This note describes the declaration-layer contract for application-native working-directory
handles that SPEC.md Section 52 declares. The normative owner is Section 52; this note restates
nothing it does not already publish.

The pure model is crates/gantry-ir/src/env_native.rs and the conformance lane is
crates/gantry-conformance/tests/env_native_directory_contract.rs. The model decides declaration,
admission, fencing, settlement, projection, and durable-exclusion questions only. It materializes
no handle, opens no directory, performs no host I/O, reads no ambient process state, and no host
adapter is part of this slice.

## Declared clauses

The section declares exactly ten clauses, in specification order:

- GNT-52.0-native-directory-foundation-scope
- GNT-52.1-native-directory-requirement-and-mapping-policy
- GNT-52.2-native-directory-path-and-fact-binding
- GNT-52.3-native-directory-exclusive-issuance-and-ownership
- GNT-52.4-native-directory-revocation-fencing
- GNT-52.5-native-directory-completion-and-late-response
- GNT-52.6-native-directory-durable-exclusion
- GNT-52.7-native-directory-child-projection
- GNT-52.8-native-directory-refusal-vocabulary
- GNT-52.9-native-directory-non-claims

## What the contract fixes

A requirement identity is the canonical capability requirement identity of the authority contract
plus one closed operation requirement kind. Every route compares that exact identity, so a stored
but uncompared identity is not authority.

A target mapping is declared data: the Linux mapping is exact and case-sensitive, and macOS is
supported through two explicit case policies. The ASCII-insensitive policy refuses non-ASCII
names rather than substituting an undeclared host fold, so no Unicode case behaviour and no
exclusive macOS lookup guarantee is claimed.

Subject facts bind the resource generation, the logical execution, the task body, and the owner
generation, so counters that coincide across executions or tasks never identify one subject. A
path text never grants authority and the handle path must equal the declared path of its attached
slot.

Issuance is exclusive: one attached slot carries at most one live handle, the handle is affine,
and a reissued slot must name a succeeding owner generation. Revocation is one live fence per
authority generation consulted by every route, so revoking fences handles already issued while
the settlement obligation survives. Completion and cancellation resolve to one winner at one
declared logical instant, and a late completion is refused without effect.

## What the contract does not fix

The contract declares no physical carrier class, no registry slot type, and no runtime facility.

A native handle never resurrects from durable state: a handle, path, or digest presentation is
refused, and only portable logical working-directory text recovers, as data only. This slice
claims no runtime implementation of any clause and no qualification of another branch.
