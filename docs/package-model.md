# Package identity, interfaces, and compatibility

This note describes the machine-checked package model in
`crates/gantry-ir/src/package.rs`. That model is `GNT-16.0` through
`GNT-16.9-resolution-order-independence`, refining the landed
`GNT-11.6-package-source-manifest` and `GNT-11.6-compatibility-classes`
relations. It is the model the specification makes normative: it is not a
registry client, not a package loader, and it reads no host path.

## Declared clauses

| Clause | What the model decides |
| --- | --- |
| `GNT-16.0` | The section's scope: manifest, interface, instance, alias, visibility, re-export, target-kind, and compatibility vocabulary, and nothing outside it. |
| `GNT-16.1-package-identity` | The canonical identity of one complete input record: name, version, source digests, selected features, declared target facts, selection record, interface digest, and generator inputs. |
| `GNT-16.2-package-instances` | One resolved instance of a package identity, bound to the interface digest it was resolved against. |
| `GNT-16.3-dependency-aliases` | Alias declarations, their namespaces, collision relations, and the refusal of an unresolved or duplicated alias. |
| `GNT-16.4-visibility` | Which recorded items a frozen interface makes nameable, and the refusal of a name it does not export. |
| `GNT-16.5-reexports` | Re-export chains that must terminate in one defining exported item, with defining package identity preserved. |
| `GNT-16.6-target-kinds` | The closed target-kind vocabulary, its per-kind entry rules, and capability requirement ceilings. |
| `GNT-16.7-public-interface-manifest` | The frozen public interface manifest, its member record, and its interface digest. |
| `GNT-16.8-compatibility-axes` | The five compatibility axes and their per-axis verdicts, including the refusal to report an unchecked axis as compatible. |
| `GNT-16.9-resolution-order-independence` | Resolution is identical under every permutation; instances deduplicate to one identity; an interface whose identity does not match its pinned dependency artifact is refused; and one distinct universe of dependencies yields one fingerprint. |

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

The model decides conditions that the specification publishes no code for:
an unpinned export, an invalid or duplicated alias, a dependency cycle, an
unknown instance, unsupported identity or interface versions, malformed
digests, malformed or duplicated declarations, omitted or undeclared or
duplicated interface members, item content that its recorded kind does not
admit, unqualified names that are neither local nor explicitly imported or that
are both at once, compatibility reports that omit or overclaim an axis, and the
dependency-fingerprint refusals of an unpinned dependency, a conflicting pin,
and the declared dependency-count ceiling.

Each such condition is a `PackageError` variant whose `code()` is `None`, and
it carries the clause that owns it through `clause()`. A condition with no
published code MUST NOT be reported under another condition's code.

## Non-claims

This model grants nothing. It invents no diagnostic identity, no interface
member, no alias spelling, and no identity input; it does not read a host path,
contact a registry, or run package source; and it does not present interface
compatibility as behavioural substitutability. The resolution-order clause
states sameness under permutation, not that any replacement preserves
behaviour.
