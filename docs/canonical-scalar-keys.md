# Canonical scalar keys

Gantry core exposes one deliberately narrow canonical-key foundation for
existing scalar values. It adds no source syntax or collection type.

Primitive type properties and `TypedPackage::type_capabilities` report this as
an explicit canonical-scalar-key eligibility predicate. It is deliberately
distinct from `is_orderable`, which only describes numeric source operators:
Unit, Bool, and String have canonical keys but are not orderable. The report
does not introduce a source capability, structural key encoding, or collection
admission.

## Eligibility and limits

Format version 1.0 admits `Unit`, `Bool`, `Int`, finite normalized `Float`, and
`String`. Lists, tuples, structs, enums, options, results, sealed `Decision`,
and sealed `OperationError` values are rejected. An application codec does not
opt a type into this sealed domain.

Every operation receives a positive finite maximum for the complete key. The
default is 4,194,325 bytes: the 21-byte frame plus four UTF-8 bytes for each
String scalar admitted by the default value limits. A too-large key reports
both the effective limit and exact required length.

## Version 1.0 frame

The bytes are, in order:

1. `GNTYKEY\0` (eight bytes);
2. unsigned big-endian `u16` major `1`;
3. unsigned big-endian `u16` minor `0`;
4. one tag: Unit `0`, Bool `1`, Int `2`, Float `3`, String `4`;
5. unsigned big-endian `u64` payload length; and
6. the payload.

Unit has an empty payload. Bool is byte `00` or `01`. Int is the admitted
signed `i64` represented as two's-complement big-endian bytes. Float is its
normalized finite IEEE binary64 bit pattern in big-endian order. String is its
exact UTF-8 sequence; Gantry performs no implicit Unicode normalization.

`CanonicalKey::from_bytes` performs bounded exact decoding of version 1.0. It
rejects bad magic, unsupported versions and tags, truncated or trailing data,
incorrect fixed-width payloads, non-Boolean Bool bytes, out-of-range Ints,
non-finite Floats, noncanonical negative zero, and invalid UTF-8. Input bytes
are retained and hashed only after the complete frame and payload are valid.

This framing is not the existing canonical JSON boundary. In particular,
canonical JSON spells both Int `1` and Float `1.0` as `1`, and spells both Unit
and an absent option as `null`; the type tag prevents those collisions.

## Equality, ordering, and hashing

The total type order is Unit, Bool, Int, Float, String. False precedes true.
Ints and Floats each use numeric order, without cross-type coercion. Strings
use lexicographic Unicode-scalar order. Consequently comparison is equal
exactly when logical value equality is equal for admitted values. Float input
normalization maps both signed zeros to positive zero before framing, ordering,
or hashing.

The deterministic content hash is SHA-256 over the exact complete frame.
It is not Rust's `Hash` implementation and does not depend on process-random
state. Hash collisions do not make unequal keys equal and do not define order.

## Compatibility

Consumers persist both format numbers as part of the bytes. A future major
format may change eligibility, framing, ordering, or hashing. A compatible
minor revision must retain every version-1.0 byte sequence and semantic result;
silent reinterpretation of stored keys is forbidden. The version-1.0 decoder
does not accept a future version speculatively.
