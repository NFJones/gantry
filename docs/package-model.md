# Package identity, interfaces, and compatibility

This note describes the package model in `crates/gantry-ir/src/package.rs` and
its machine-checked evidence in
`crates/gantry-conformance/tests/package_identity.rs`. The specification is
normative; the crate models `GNT-16.0` through
`GNT-16.9-resolution-order-independence`, refining the landed
`GNT-11.6-package-source-manifest` and `GNT-11.6-compatibility-classes`
relations. The model is not a registry client, not a package loader, and it
reads no host path.

## Declared clauses

| Clause | What the model decides |
| --- | --- |
| `GNT-16.0` | The section's scope: the closed vocabulary of package identity and resolution order, manifests, interfaces, instances, aliases, visibility, re-exports, target kinds, and compatibility axes; a term outside that vocabulary is admitted by no clause of this section. |
| `GNT-16.1-package-identity` | The canonical identity of one resolved package, computed over exactly these inputs and no others: resolved package name, exact version, canonical source-identity digest, selected features, target facts, public-interface digest, and declared generator inputs. |
| `GNT-16.2-package-instances` | One resolved package at one exact version with one selected feature solution: distinct instance identities are distinct nominal universes even when their items are structurally identical, and an item of one instance is not interchangeable with a structurally identical item of another without an explicit source conversion. |
| `GNT-16.3-dependency-aliases` | Alias declarations, their namespaces, collision relations, and the refusal of an unresolved or duplicated alias. |
| `GNT-16.4-visibility` | Which recorded items a frozen interface makes nameable, and the refusal of a name it does not export. |
| `GNT-16.5-reexports` | Re-export chains that must terminate in one defining exported item, with defining package identity preserved. |
| `GNT-16.6-target-kinds` | The closed target-kind vocabulary, its per-kind entry rules, and capability requirement ceilings. |
| `GNT-16.7-public-interface-manifest` | The frozen public interface manifest, its member record, and its interface digest. |
| `GNT-16.8-compatibility-axes` | The five compatibility axes and their per-axis verdicts, including the refusal to report an unchecked axis as compatible. |
| `GNT-16.9-resolution-order-independence` | Four rules: resolution never varies with discovery, enumeration, graph-path, or response order; distinct resolved versions and feature-distinct instances are distinct nominal universes whose items are not interchangeable; identical package instances deduplicate to exactly one identity; and a stale interface whose identity does not match its pinned dependency artifact MUST NOT link. The model additionally derives one dependency fingerprint per distinct resolved dependency set; that fingerprint is the model's own value and not a term of the clause. |

The four rules of `GNT-16.9-resolution-order-independence`, and every other
clause of Section 16, are `not-applicable` under a v1 profile, where no package
is resolved, loaded, or linked as a dependency of another package. This note
publishes the model without asserting that any run exercises it.

## Registered diagnostic codes

These seven codes are frozen. A consumer matches the code spelling, never a
message; a meaning changes only with the clause that owns it.

| Code | Registered meaning | Owning clause |
| --- | --- | --- |
| `package-alias-collision` | A dependency alias collides with another name in its declaring package instance. | `GNT-16.3-dependency-aliases` |
| `package-alias-unresolved` | A qualified path names a dependency alias that its declaring package instance does not declare. | `GNT-16.3-dependency-aliases` |
| `package-instance-interface-mismatch` | A package interface does not match the interface identity bound by its package instance or pinned dependency artifact. | `GNT-16.7-public-interface-manifest` |
| `package-item-not-exported` | A name is not exported by the frozen public interface manifest that governs it. | `GNT-16.4-visibility` |
| `package-reexport-cycle` | A re-export chain never terminates in a defining exported item. | `GNT-16.5-reexports` |
| `package-target-kind-invalid` | A target violates the closed target-kind vocabulary or the rules of its kind. | `GNT-16.6-target-kinds` |
| `package-transitive-undeclared` | A package names an item reachable only through a dependency it does not declare. | `GNT-16.3-dependency-aliases` |

## Conditions without a published code

The model decides conditions that the specification publishes no code for. They
include:

- an unpinned export;
- an invalid or duplicated alias;
- a dependency cycle, or an unknown instance;
- an unsupported identity or interface version, or a malformed digest;
- a malformed or duplicated declaration, an omitted, undeclared, or duplicated
  interface member, or item content that its recorded kind does not admit;
- an unqualified name that is neither local nor explicitly imported, or that is
  both at once;
- a resolved requirement that exceeds a declared capability ceiling;
- an identity record carrying an undefined property;
- a compatibility report that omits or overclaims an axis;
- a dependency-fingerprint refusal: an unpinned dependency, a conflicting pin,
  or the declared dependency-count ceiling.

Each such condition is a `PackageError` variant whose `code()` is `None`, and
it carries the clause that owns it through `clause()`. A condition with no
published code MUST NOT be reported under another condition's code.

## Non-claims

This model grants nothing. It invents no diagnostic identity, no interface
member, no alias spelling, and no identity input; it does not read a host path,
contact a registry, or run package source; and it does not present interface
compatibility as behavioural substitutability. The resolution-order clause
states sameness under permutation, not that any replacement preserves
behaviour. The model holds no package-wide state created by linking a package,
because package state is created by explicit execution; and a `Debug` or
`Display` rendering of these types is presentation only and is never a protocol
identity.
