//! The crypto foundation of `GNT-44.0-crypto-foundation-scope` and
//! `GNT-44.1-crypto-algorithm-contract`: the declared `std.crypto` family with its `hash` and
//! `signature` modules, the versioned algorithm identity and its exact admission rule, the frozen
//! refusal vocabulary with its declared refusal categories, and the separation between these pure
//! read-only algorithms and signing, secret-key material, credentials, and protected operations,
//! which host capabilities alone own.
//!
//! The model is pure: it consumes no platform cryptographic API, host crypto library, hardware
//! facility, ambient provider registry, random source, timing, environment, locale, filesystem,
//! or global mutable state. The content-hashing algorithm of `GNT-44.2-content-hashing` is
//! declared here; every other algorithm's own clause publishes its digest or verification
//! contract, vectors, and bounds.

use crate::stdlib::{
    NameClass, PackageFamily, StabilityTier, StdGraph, StdItem, StdlibDiagnosticCode, StdlibError,
};

/// The declared clauses of Section 44, in specification order.
pub const CRYPTO_CLAUSES: [&str; 5] = [
    "GNT-44.0-crypto-foundation-scope",
    "GNT-44.1-crypto-algorithm-contract",
    "GNT-44.2-content-hashing",
    "GNT-44.3-signature-verification",
    "GNT-44.4-crypto-non-claims",
];

/// The one declared version of every algorithm in this revision
/// (`GNT-44.1-crypto-algorithm-contract`).
pub const DECLARED_ALGORITHM_VERSION: u16 = 1;

/// The declared input octet bound of the content-hashing algorithm
/// (`GNT-44.2-content-hashing`): the largest octet count a content-hashing operation admits.
pub const SHA256_INPUT_OCTET_BOUND: usize = 1_048_576;

/// The declared digest octet length of the content-hashing algorithm
/// (`GNT-44.2-content-hashing`).
pub const SHA256_DIGEST_OCTET_LENGTH: usize = 32;

/// The declared public-key octet length of the signature algorithm
/// (`GNT-44.3-signature-verification`).
pub const ED25519_PUBLIC_KEY_OCTET_LENGTH: usize = 32;

/// The declared signature octet length of the signature algorithm
/// (`GNT-44.3-signature-verification`).
pub const ED25519_SIGNATURE_OCTET_LENGTH: usize = 64;

/// The declared message octet bound of the signature algorithm
/// (`GNT-44.3-signature-verification`).
pub const ED25519_MESSAGE_OCTET_BOUND: usize = 1_048_576;

/// One declared verification verdict of the signature algorithm
/// (`GNT-44.3-signature-verification`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ed25519Verdict {
    /// The presented signature is the algorithm's signature of the presented message under the
    /// presented public key.
    Accepted,
    /// The presented signature is not the algorithm's signature of the presented message under
    /// the presented public key.
    Refused,
}

impl Ed25519Verdict {
    /// The closed declared set, in canonical wire-name order.
    pub const ALL: [Ed25519Verdict; 2] = [Self::Accepted, Self::Refused];

    /// Returns the canonical wire spelling (`GNT-44.3-signature-verification`).
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Refused => "refused",
        }
    }
}

/// One declared non-claim of Section 44 (`GNT-44.4-crypto-non-claims`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoNonClaim {
    /// No ambient registry, display label, or host facility selects an algorithm or version.
    AmbientSelection,
    /// No observation of this section is a canonical boundary encoding.
    BoundaryEncoding,
    /// No clause of this section claims a timing or side-channel property.
    ConstantTime,
    /// No observation of this section is durable state or a recovery input.
    DurableEligibility,
    /// No observation of this section is an `ExternalValue`, a protected release, or a capability.
    ExternalEligibility,
    /// No platform or host cryptographic facility is a semantic authority.
    HostCryptoAuthority,
    /// No algorithm of this section signs, decrypts, or touches a secret key or credential.
    SecretKeyOperations,
    /// No clause of this section claims a cryptographic security property.
    SecurityProperty,
}

impl CryptoNonClaim {
    /// The closed declared set, in canonical wire-name order.
    pub const ALL: [CryptoNonClaim; 8] = [
        Self::AmbientSelection,
        Self::BoundaryEncoding,
        Self::ConstantTime,
        Self::DurableEligibility,
        Self::ExternalEligibility,
        Self::HostCryptoAuthority,
        Self::SecretKeyOperations,
        Self::SecurityProperty,
    ];

    /// Returns the canonical wire spelling (`GNT-44.4-crypto-non-claims`).
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::AmbientSelection => "ambient-selection",
            Self::BoundaryEncoding => "boundary-encoding",
            Self::ConstantTime => "constant-time",
            Self::DurableEligibility => "durable-eligibility",
            Self::ExternalEligibility => "external-eligibility",
            Self::HostCryptoAuthority => "host-crypto-authority",
            Self::SecretKeyOperations => "secret-key-operations",
            Self::SecurityProperty => "security-property",
        }
    }

    /// Returns the published meaning of this non-claim.
    #[must_use]
    pub const fn meaning(self) -> &'static str {
        match self {
            Self::AmbientSelection => {
                "No ambient registry, display label, or host facility selects an algorithm or version."
            }
            Self::BoundaryEncoding => {
                "No digest, verdict, or refusal of this section is a canonical boundary encoding."
            }
            Self::ConstantTime => {
                "No clause of this section claims a timing or side-channel property."
            }
            Self::DurableEligibility => {
                "No digest, verdict, or refusal of this section is durable state or a recovery input."
            }
            Self::ExternalEligibility => {
                "No digest, verdict, or refusal of this section is an `ExternalValue`, a protected release, or a capability."
            }
            Self::HostCryptoAuthority => {
                "No platform cryptographic API, host crypto library, hardware facility, or entropy source is a semantic authority."
            }
            Self::SecretKeyOperations => {
                "No algorithm of this section signs, decrypts, or touches a secret key or credential."
            }
            Self::SecurityProperty => {
                "No clause of this section claims a cryptographic security property."
            }
        }
    }

    /// Decodes one canonical wire spelling; every other spelling is `None`.
    #[must_use]
    pub fn from_wire_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|non_claim| non_claim.wire_name() == name)
    }

    /// Returns the one owning clause of this non-claim.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-44.4-crypto-non-claims"
    }
}

/// The declared non-claims of Section 44, in canonical wire-name order
/// (`GNT-44.4-crypto-non-claims`).
pub const CRYPTO_NON_CLAIMS: [CryptoNonClaim; 8] = CryptoNonClaim::ALL;

/// One declared module of the `std.crypto` family (`GNT-44.1-crypto-algorithm-contract`).
///
/// The declared set is closed and its canonical order ([`CryptoModule::ALL`]) is its canonical
/// module name order.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CryptoModule {
    /// The `std.crypto::hash` module.
    Hash,
    /// The `std.crypto::signature` module.
    Signature,
}

impl CryptoModule {
    /// The closed declared set, in canonical name order.
    pub const ALL: [CryptoModule; 2] = [Self::Hash, Self::Signature];

    /// Returns the wire spelling of this module (`GNT-44.1-crypto-algorithm-contract`).
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Hash => "hash",
            Self::Signature => "signature",
        }
    }

    /// Returns the canonical logical module name of this module
    /// (`GNT-34.1-canonical-hierarchy-and-package-names`).
    #[must_use]
    pub const fn module_name(self) -> &'static str {
        match self {
            Self::Hash => "std.crypto::hash",
            Self::Signature => "std.crypto::signature",
        }
    }

    /// Returns the algorithm this module declares in this revision
    /// (`GNT-44.1-crypto-algorithm-contract`).
    #[must_use]
    pub const fn declared_algorithm(self) -> &'static str {
        match self {
            Self::Hash => "sha256",
            Self::Signature => "ed25519",
        }
    }

    /// Returns the one declared identity of this module
    /// (`GNT-44.1-crypto-algorithm-contract`).
    #[must_use]
    pub const fn declared_identity(self) -> AlgorithmIdentity {
        AlgorithmIdentity {
            module: self,
            algorithm: self.declared_algorithm(),
            version: DECLARED_ALGORITHM_VERSION,
        }
    }

    /// Decodes one canonical module name; every other spelling is `None`.
    #[must_use]
    pub fn from_module_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|module| module.module_name() == name)
    }
}

/// One selected algorithm identity of `GNT-44.1-crypto-algorithm-contract`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AlgorithmIdentity {
    module: CryptoModule,
    algorithm: &'static str,
    version: u16,
}

impl AlgorithmIdentity {
    /// Publishes the one declared identity of one module
    /// (`GNT-44.1-crypto-algorithm-contract`).
    #[must_use]
    pub const fn declared(module: CryptoModule) -> Self {
        module.declared_identity()
    }

    /// Admits exactly one declared algorithm identity of
    /// `GNT-44.1-crypto-algorithm-contract`.
    ///
    /// The canonical identity spelling is `std.crypto::<module>::<algorithm>@<version>`. An
    /// identity naming an undeclared module, an undeclared algorithm, or an undeclared version is
    /// refused under `crypto-unsupported-algorithm`, naming the observed spelling and the declared
    /// identity, or the declared set when no declared module is named, rather than substituted,
    /// upgraded, downgraded, negotiated by a display label, inferred from input, or approximated.
    /// The presented version text is admitted only when it is exactly the canonical spelling of
    /// the declared version: a parseable variant such as a leading zero or a sign is refused,
    /// never normalized to the declared version.
    pub fn admit(presented: &str) -> Result<Self, CryptoError> {
        let Some((identity, version)) = presented.rsplit_once('@') else {
            return Err(Self::undeclared_identity(presented));
        };
        let Some((module_name, algorithm)) = identity.rsplit_once("::") else {
            return Err(Self::undeclared_identity(presented));
        };
        let Some(module) = CryptoModule::from_module_name(module_name) else {
            return Err(Self::undeclared_identity(presented));
        };
        let declared = module.declared_identity();
        if algorithm != declared.algorithm || version != DECLARED_ALGORITHM_VERSION.to_string() {
            return Err(CryptoError::new(
                CryptoDiagnosticCode::UnsupportedAlgorithm,
                format!(
                    "`{presented}` is not the declared algorithm identity `{}`",
                    declared.canonical_identity()
                ),
            ));
        }
        Ok(declared)
    }

    /// Publishes the refusal of one identity that names no declared module
    /// (`GNT-44.1-crypto-algorithm-contract`).
    fn undeclared_identity(presented: &str) -> CryptoError {
        let declared = CryptoModule::ALL
            .iter()
            .map(|module| format!("`{}`", module.declared_identity().canonical_identity()))
            .collect::<Vec<_>>()
            .join(", ");
        CryptoError::new(
            CryptoDiagnosticCode::UnsupportedAlgorithm,
            format!(
                "`{presented}` names no declared algorithm identity; the declared identities are {declared}"
            ),
        )
    }

    /// Returns the canonical identity spelling `std.crypto::<module>::<algorithm>@<version>`
    /// (`GNT-44.1-crypto-algorithm-contract`).
    #[must_use]
    pub fn canonical_identity(self) -> String {
        format!(
            "{}::{}@{}",
            self.module.module_name(),
            self.algorithm,
            self.version
        )
    }

    /// Returns the declared module.
    #[must_use]
    pub const fn module(self) -> CryptoModule {
        self.module
    }

    /// Returns the declared algorithm.
    #[must_use]
    pub const fn algorithm(self) -> &'static str {
        self.algorithm
    }

    /// Returns the declared version.
    #[must_use]
    pub const fn version(self) -> u16 {
        self.version
    }
}

/// One declared refusal category of `GNT-44.1-crypto-algorithm-contract`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoRefusalCategory {
    /// Input outside an algorithm's declared admitted language.
    MalformedInput,
    /// An identity naming an undeclared module, algorithm, or version.
    UnsupportedAlgorithm,
    /// An operation beyond a declared input or work bound.
    WorkLimit,
}

impl CryptoRefusalCategory {
    /// The closed declared set, in canonical wire order.
    pub const ALL: [CryptoRefusalCategory; 3] = [
        Self::MalformedInput,
        Self::UnsupportedAlgorithm,
        Self::WorkLimit,
    ];

    /// Returns the canonical wire spelling (`GNT-44.1-crypto-algorithm-contract`).
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::MalformedInput => "malformed-input",
            Self::UnsupportedAlgorithm => "unsupported-algorithm",
            Self::WorkLimit => "work-limit",
        }
    }

    /// Decodes one canonical wire spelling; every other spelling is `None`.
    #[must_use]
    pub fn from_wire_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|category| category.wire_name() == name)
    }
}

/// One frozen crypto refusal of `GNT-44.1-crypto-algorithm-contract`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoDiagnosticCode {
    /// Input outside an algorithm's declared admitted language.
    MalformedInput,
    /// An identity naming an undeclared module, algorithm, or version.
    UnsupportedAlgorithm,
    /// An operation beyond a declared input or work bound.
    WorkLimit,
}

impl CryptoDiagnosticCode {
    /// The closed declared set, in canonical spelling order.
    pub const ALL: [CryptoDiagnosticCode; 3] = [
        Self::MalformedInput,
        Self::UnsupportedAlgorithm,
        Self::WorkLimit,
    ];

    /// Returns the frozen refusal spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MalformedInput => "crypto-malformed-input",
            Self::UnsupportedAlgorithm => "crypto-unsupported-algorithm",
            Self::WorkLimit => "crypto-work-limit",
        }
    }

    /// Returns the published meaning of this refusal.
    #[must_use]
    pub const fn meaning(self) -> &'static str {
        match self {
            Self::MalformedInput => {
                "Input outside an algorithm's declared admitted language is refused."
            }
            Self::UnsupportedAlgorithm => {
                "An identity naming an undeclared module, algorithm, or version is refused."
            }
            Self::WorkLimit => "An operation beyond a declared input or work bound is refused.",
        }
    }

    /// Returns the one owning clause of this refusal
    /// (`GNT-44.1-crypto-algorithm-contract`).
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-44.1-crypto-algorithm-contract"
    }

    /// Returns the one refusal category this refusal classifies under
    /// (`GNT-44.1-crypto-algorithm-contract`).
    #[must_use]
    pub const fn category(self) -> CryptoRefusalCategory {
        match self {
            Self::MalformedInput => CryptoRefusalCategory::MalformedInput,
            Self::UnsupportedAlgorithm => CryptoRefusalCategory::UnsupportedAlgorithm,
            Self::WorkLimit => CryptoRefusalCategory::WorkLimit,
        }
    }
}

/// One refusal of the crypto foundation (`GNT-44.1-crypto-algorithm-contract`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CryptoError {
    code: CryptoDiagnosticCode,
    detail: String,
}

impl CryptoError {
    /// Publishes one refusal of the named code.
    #[must_use]
    pub fn new(code: CryptoDiagnosticCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    /// Returns the frozen refusal code.
    #[must_use]
    pub const fn code(&self) -> CryptoDiagnosticCode {
        self.code
    }

    /// Returns the refusal detail.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// Returns the one owning clause of this refusal
    /// (`GNT-44.1-crypto-algorithm-contract`).
    #[must_use]
    pub fn requirement(&self) -> &'static str {
        self.code.requirement()
    }

    /// Returns the one refusal category this refusal classifies under
    /// (`GNT-44.1-crypto-algorithm-contract`).
    #[must_use]
    pub fn category(&self) -> CryptoRefusalCategory {
        self.code.category()
    }
}

/// The declared initial hash values of the content-hashing algorithm
/// (`GNT-44.2-content-hashing`).
const SHA256_INITIAL_HASH_VALUES: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// The declared round constants of the content-hashing algorithm
/// (`GNT-44.2-content-hashing`).
const SHA256_ROUND_CONSTANTS: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// One content digest of `GNT-44.2-content-hashing`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sha256Digest {
    octets: [u8; SHA256_DIGEST_OCTET_LENGTH],
}

impl Sha256Digest {
    /// Returns the digest's declared octets (`GNT-44.2-content-hashing`): the eight digest state
    /// words in order, each as four big-endian octets.
    #[must_use]
    pub const fn octets(&self) -> &[u8; SHA256_DIGEST_OCTET_LENGTH] {
        &self.octets
    }
}

/// Publishes the content digest of one octet sequence under the declared algorithm of
/// `GNT-44.2-content-hashing`.
///
/// The digest is the declared algorithm's decision over the presented octets: an admitted
/// sequence publishes exactly one thirty-two-octet digest, decided by those octets alone. A
/// sequence holding more than `SHA256_INPUT_OCTET_BOUND` octets is refused under
/// `crypto-work-limit`, naming the observed octet count and the declared bound, before any part
/// of the excess is examined and before any digest state is initialized.
pub fn sha256_digest(octets: &[u8]) -> Result<Sha256Digest, CryptoError> {
    if octets.len() > SHA256_INPUT_OCTET_BOUND {
        return Err(CryptoError::new(
            CryptoDiagnosticCode::WorkLimit,
            format!(
                "the presented octet sequence holds {} octets, beyond the declared bound {SHA256_INPUT_OCTET_BOUND}",
                octets.len()
            ),
        ));
    }
    let mut padded = Vec::with_capacity(octets.len() + 72);
    padded.extend_from_slice(octets);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&((octets.len() as u64) * 8).to_be_bytes());
    let mut state = SHA256_INITIAL_HASH_VALUES;
    for block in padded.chunks_exact(64) {
        sha256_compress(&mut state, block);
    }
    let mut digest = [0_u8; SHA256_DIGEST_OCTET_LENGTH];
    for (index, word) in state.iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    Ok(Sha256Digest { octets: digest })
}

/// Compresses one padded-message block into the digest state (`GNT-44.2-content-hashing`).
fn sha256_compress(state: &mut [u32; 8], block: &[u8]) {
    let mut words = [0_u32; 64];
    for (index, chunk) in block.chunks_exact(4).enumerate() {
        words[index] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    for index in 16..64 {
        let schedule_upper = words[index - 15].rotate_right(7)
            ^ words[index - 15].rotate_right(18)
            ^ (words[index - 15] >> 3);
        let schedule_lower = words[index - 2].rotate_right(17)
            ^ words[index - 2].rotate_right(19)
            ^ (words[index - 2] >> 10);
        words[index] = words[index - 16]
            .wrapping_add(schedule_upper)
            .wrapping_add(words[index - 7])
            .wrapping_add(schedule_lower);
    }
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];
    for (index, word) in words.iter().enumerate() {
        let choose = (e & f) ^ (!e & g);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let upper = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let lower = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let first = h
            .wrapping_add(upper)
            .wrapping_add(choose)
            .wrapping_add(SHA256_ROUND_CONSTANTS[index])
            .wrapping_add(*word);
        let second = lower.wrapping_add(majority);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(first);
        d = c;
        c = b;
        b = a;
        a = first.wrapping_add(second);
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/// The declared initial hash values of the signature algorithm's hash function
/// (`GNT-44.3-signature-verification`).
const SHA512_INITIAL_HASH_VALUES: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

/// The declared round constants of the signature algorithm's hash function
/// (`GNT-44.3-signature-verification`).
const SHA512_ROUND_CONSTANTS: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

/// Publishes the declared hash function of the signature algorithm
/// (`GNT-44.3-signature-verification`) over one octet sequence.
fn sha512_digest(octets: &[u8]) -> [u8; 64] {
    let mut padded = Vec::with_capacity(octets.len() + 144);
    padded.extend_from_slice(octets);
    padded.push(0x80);
    while padded.len() % 128 != 112 {
        padded.push(0);
    }
    padded.extend_from_slice(&((octets.len() as u128) * 8).to_be_bytes());
    let mut state = SHA512_INITIAL_HASH_VALUES;
    for block in padded.chunks_exact(128) {
        sha512_compress(&mut state, block);
    }
    let mut digest = [0_u8; 64];
    for (index, word) in state.iter().enumerate() {
        digest[index * 8..index * 8 + 8].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

/// Compresses one padded-message block into the hash state of the signature algorithm
/// (`GNT-44.3-signature-verification`).
fn sha512_compress(state: &mut [u64; 8], block: &[u8]) {
    let mut words = [0_u64; 80];
    for (index, chunk) in block.chunks_exact(8).enumerate() {
        words[index] = u64::from_be_bytes([
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
        ]);
    }
    for index in 16..80 {
        let schedule_upper = words[index - 15].rotate_right(1)
            ^ words[index - 15].rotate_right(8)
            ^ (words[index - 15] >> 7);
        let schedule_lower = words[index - 2].rotate_right(19)
            ^ words[index - 2].rotate_right(61)
            ^ (words[index - 2] >> 6);
        words[index] = words[index - 16]
            .wrapping_add(schedule_upper)
            .wrapping_add(words[index - 7])
            .wrapping_add(schedule_lower);
    }
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];
    for (index, word) in words.iter().enumerate() {
        let choose = (e & f) ^ (!e & g);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let upper = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let lower = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
        let first = h
            .wrapping_add(upper)
            .wrapping_add(choose)
            .wrapping_add(SHA512_ROUND_CONSTANTS[index])
            .wrapping_add(*word);
        let second = lower.wrapping_add(majority);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(first);
        d = c;
        c = b;
        b = a;
        a = first.wrapping_add(second);
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/// The declared 51-bit limb mask of the signature algorithm's field
/// (`GNT-44.3-signature-verification`).
const ED25519_FIELD_MASK: u64 = (1 << 51) - 1;

/// One declared field element of the signature algorithm
/// (`GNT-44.3-signature-verification`): five 51-bit limbs of the field modulus `2^255 - 19`,
/// least significant limb first.
#[derive(Clone, Copy, Debug)]
struct Ed25519Field([u64; 5]);

impl Ed25519Field {
    /// The declared field zero.
    const ZERO: Ed25519Field = Ed25519Field([0, 0, 0, 0, 0]);

    /// The declared field one.
    const ONE: Ed25519Field = Ed25519Field([1, 0, 0, 0, 0]);

    /// Carries the limbs into the declared 51-bit range.
    fn carry(mut limbs: [u64; 5]) -> Ed25519Field {
        let mut carry = limbs[0] >> 51;
        limbs[0] &= ED25519_FIELD_MASK;
        limbs[1] += carry;
        carry = limbs[1] >> 51;
        limbs[1] &= ED25519_FIELD_MASK;
        limbs[2] += carry;
        carry = limbs[2] >> 51;
        limbs[2] &= ED25519_FIELD_MASK;
        limbs[3] += carry;
        carry = limbs[3] >> 51;
        limbs[3] &= ED25519_FIELD_MASK;
        limbs[4] += carry;
        carry = limbs[4] >> 51;
        limbs[4] &= ED25519_FIELD_MASK;
        limbs[0] += carry * 19;
        carry = limbs[0] >> 51;
        limbs[0] &= ED25519_FIELD_MASK;
        limbs[1] += carry;
        Ed25519Field(limbs)
    }

    /// Adds two field elements.
    fn add(&self, other: &Ed25519Field) -> Ed25519Field {
        let mut limbs = [0_u64; 5];
        for (index, limb) in limbs.iter_mut().enumerate() {
            *limb = self.0[index] + other.0[index];
        }
        Ed25519Field::carry(limbs)
    }

    /// Subtracts two field elements.
    fn sub(&self, other: &Ed25519Field) -> Ed25519Field {
        // Adding four times the declared modulus keeps every limb nonnegative.
        const FOUR_MODULUS: [u64; 5] = [
            (1 << 52) - 76,
            (1 << 52) - 2,
            (1 << 52) - 2,
            (1 << 52) - 2,
            (1 << 53) - 2,
        ];
        let mut limbs = [0_u64; 5];
        for (index, limb) in limbs.iter_mut().enumerate() {
            *limb = self.0[index] + FOUR_MODULUS[index] - other.0[index];
        }
        Ed25519Field::carry(limbs)
    }

    /// Negates one field element.
    fn negate(&self) -> Ed25519Field {
        Ed25519Field::ZERO.sub(self)
    }

    /// Multiplies two field elements.
    fn multiply(&self, other: &Ed25519Field) -> Ed25519Field {
        let left = self.0;
        let right = other.0;
        let left = left.map(u128::from);
        let right = right.map(u128::from);
        let radix = 19_u128;
        let mut reduced = [0_u128; 5];
        reduced[0] = left[0] * right[0]
            + radix
                * (left[1] * right[4]
                    + left[2] * right[3]
                    + left[3] * right[2]
                    + left[4] * right[1]);
        reduced[1] = left[0] * right[1]
            + left[1] * right[0]
            + radix * (left[2] * right[4] + left[3] * right[3] + left[4] * right[2]);
        reduced[2] = left[0] * right[2]
            + left[1] * right[1]
            + left[2] * right[0]
            + radix * (left[3] * right[4] + left[4] * right[3]);
        reduced[3] = left[0] * right[3]
            + left[1] * right[2]
            + left[2] * right[1]
            + left[3] * right[0]
            + radix * (left[4] * right[4]);
        reduced[4] = left[0] * right[4]
            + left[1] * right[3]
            + left[2] * right[2]
            + left[3] * right[1]
            + left[4] * right[0];
        let mut limbs = [0_u64; 5];
        let mut carry = reduced[0] >> 51;
        limbs[0] = reduced[0] as u64 & ED25519_FIELD_MASK;
        let index_one = reduced[1] + carry;
        carry = index_one >> 51;
        limbs[1] = index_one as u64 & ED25519_FIELD_MASK;
        let index_two = reduced[2] + carry;
        carry = index_two >> 51;
        limbs[2] = index_two as u64 & ED25519_FIELD_MASK;
        let index_three = reduced[3] + carry;
        carry = index_three >> 51;
        limbs[3] = index_three as u64 & ED25519_FIELD_MASK;
        let index_four = reduced[4] + carry;
        carry = index_four >> 51;
        limbs[4] = index_four as u64 & ED25519_FIELD_MASK;
        limbs[0] += carry as u64 * 19;
        Ed25519Field::carry(limbs)
    }

    /// Squares one field element.
    fn square(&self) -> Ed25519Field {
        self.multiply(self)
    }

    /// Publishes the canonical little-endian octets of one field element.
    fn octets(&self) -> [u8; 32] {
        const MODULUS_LIMBS: [u64; 5] = [
            (1 << 51) - 19,
            (1 << 51) - 1,
            (1 << 51) - 1,
            (1 << 51) - 1,
            (1 << 51) - 1,
        ];
        let mut limbs = Ed25519Field::carry(self.0).0;
        limbs = Ed25519Field::carry(limbs).0;
        let mut greater = false;
        let mut equal = true;
        for index in (0..5).rev() {
            if limbs[index] > MODULUS_LIMBS[index] {
                greater = true;
                break;
            }
            if limbs[index] < MODULUS_LIMBS[index] {
                equal = false;
                break;
            }
        }
        if greater || equal {
            let mut borrow = 0_i128;
            for index in 0..5 {
                let value = i128::from(limbs[index]) - i128::from(MODULUS_LIMBS[index]) - borrow;
                if value < 0 {
                    limbs[index] = (value + (1 << 51)) as u64;
                    borrow = 1;
                } else {
                    limbs[index] = value as u64;
                    borrow = 0;
                }
            }
        }
        let mut octets = [0_u8; 32];
        let mut bit = 0_usize;
        for limb in limbs {
            let mut remaining = limb;
            let mut remaining_bits = 51_usize;
            while remaining_bits > 0 {
                let byte = bit / 8;
                let offset = bit % 8;
                let take = (8 - offset).min(remaining_bits);
                let mask = (1_u64 << take) - 1;
                octets[byte] |= ((remaining & mask) as u8) << offset;
                remaining >>= take;
                remaining_bits -= take;
                bit += take;
            }
        }
        octets
    }

    /// Admits the canonical little-endian octets of one field element.
    fn from_octets(octets: &[u8; 32]) -> Ed25519Field {
        let load = |offset: usize| -> u64 {
            let mut value = 0_u64;
            for index in 0..8 {
                value |= u64::from(octets[offset + index]) << (8 * index);
            }
            value
        };
        Ed25519Field([
            load(0) & ED25519_FIELD_MASK,
            (load(6) >> 3) & ED25519_FIELD_MASK,
            (load(12) >> 6) & ED25519_FIELD_MASK,
            (load(19) >> 1) & ED25519_FIELD_MASK,
            (load(24) >> 12) & ED25519_FIELD_MASK,
        ])
    }

    /// Returns whether the field element is the field zero.
    fn is_zero(&self) -> bool {
        self.octets() == [0_u8; 32]
    }

    /// Returns whether the field element's canonical least significant bit is one.
    fn is_odd(&self) -> bool {
        self.octets()[0] & 1 == 1
    }

    /// Returns whether two field elements are the same field element.
    fn equals(&self, other: &Ed25519Field) -> bool {
        self.octets() == other.octets()
    }

    /// Publishes one field power by the declared square-and-multiply chain.
    fn pow(&self, exponent_bits: impl Fn(usize) -> bool, highest: usize) -> Ed25519Field {
        let mut result = Ed25519Field::ONE;
        for bit in (0..=highest).rev() {
            result = result.square();
            if exponent_bits(bit) {
                result = result.multiply(self);
            }
        }
        result
    }

    /// Publishes the declared power `z^((p - 5) / 8)`.
    fn pow_p_minus_five_over_eight(&self) -> Ed25519Field {
        self.pow(|bit| bit != 1, 251)
    }

    /// Publishes the declared square root of minus one.
    fn sqrt_minus_one() -> Ed25519Field {
        Ed25519Field([2, 0, 0, 0, 0]).pow(|bit| bit != 2, 252)
    }
}

/// The declared group order of the signature algorithm, little-endian
/// (`GNT-44.3-signature-verification`).
const ED25519_GROUP_ORDER: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// The declared curve constant `d`, little-endian (`GNT-44.3-signature-verification`).
const ED25519_CURVE_D: [u8; 32] = [
    0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75, 0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
    0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c, 0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52,
];

/// The declared base point, encoded as the canonical `4/5` with an even `x`
/// (`GNT-44.3-signature-verification`).
const ED25519_BASE_POINT_ENCODED: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

/// The declared base point's `x`, little-endian (`GNT-44.3-signature-verification`).
const ED25519_BASE_POINT_X: [u8; 32] = [
    0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9, 0xb2, 0xa7, 0x25, 0x95, 0x60, 0xc7, 0x2c, 0x69,
    0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2, 0xa4, 0xc0, 0xfe, 0x53, 0x6e, 0xcd, 0xd3, 0x36, 0x69, 0x21,
];

/// One declared point of the signature algorithm's curve in extended coordinates
/// (`GNT-44.3-signature-verification`).
#[derive(Clone, Copy, Debug)]
struct Ed25519Point {
    x: Ed25519Field,
    y: Ed25519Field,
    z: Ed25519Field,
    t: Ed25519Field,
}

impl Ed25519Point {
    /// The declared neutral point.
    const IDENTITY: Ed25519Point = Ed25519Point {
        x: Ed25519Field::ZERO,
        y: Ed25519Field::ONE,
        z: Ed25519Field::ONE,
        t: Ed25519Field::ZERO,
    };

    /// The declared curve constant `2*d`.
    fn two_d() -> Ed25519Field {
        let d = Ed25519Field::from_octets(&ED25519_CURVE_D);
        d.add(&d)
    }

    /// Adds two declared curve points.
    fn add(&self, other: &Ed25519Point) -> Ed25519Point {
        let first = self.y.sub(&self.x).multiply(&other.y.sub(&other.x));
        let second = self.y.add(&self.x).multiply(&other.y.add(&other.x));
        let third = self.t.multiply(&other.t).multiply(&Ed25519Point::two_d());
        let two = Ed25519Field([2, 0, 0, 0, 0]);
        let fourth = self.z.multiply(&other.z).multiply(&two);
        let fifth = second.sub(&first);
        let sixth = fourth.sub(&third);
        let seventh = fourth.add(&third);
        let eighth = second.add(&first);
        Ed25519Point {
            x: fifth.multiply(&sixth),
            y: seventh.multiply(&eighth),
            t: fifth.multiply(&eighth),
            z: sixth.multiply(&seventh),
        }
    }

    /// Doubles one declared curve point.
    fn double(&self) -> Ed25519Point {
        let two = Ed25519Field([2, 0, 0, 0, 0]);
        let first = self.x.square();
        let second = self.y.square();
        let third = self.z.square().multiply(&two);
        let fourth = first.negate();
        let fifth = self.x.add(&self.y).square().sub(&first).sub(&second);
        let seventh = fourth.add(&second);
        let sixth = seventh.sub(&third);
        let eighth = fourth.sub(&second);
        Ed25519Point {
            x: fifth.multiply(&sixth),
            y: seventh.multiply(&eighth),
            t: fifth.multiply(&eighth),
            z: sixth.multiply(&seventh),
        }
    }

    /// Publishes the declared scalar multiple of one point.
    fn multiply(&self, scalar: &[u8; 32]) -> Ed25519Point {
        let mut result = Ed25519Point::IDENTITY;
        for octet in scalar.iter().rev() {
            for bit in (0..8).rev() {
                result = result.double();
                if (octet >> bit) & 1 == 1 {
                    result = result.add(self);
                }
            }
        }
        result
    }

    /// Returns whether two declared curve points are the same point.
    fn equals(&self, other: &Ed25519Point) -> bool {
        self.x.multiply(&other.z).equals(&other.x.multiply(&self.z))
            && self.y.multiply(&other.z).equals(&other.y.multiply(&self.z))
    }
}

/// Admits one declared curve point from its canonical encoding
/// (`GNT-44.3-signature-verification`).
fn ed25519_decode_point(encoded: &[u8; 32]) -> Option<Ed25519Point> {
    let sign = (encoded[31] >> 7) & 1 == 1;
    let y = Ed25519Field::from_octets(encoded);
    let mut check = *encoded;
    check[31] &= 0x7f;
    if y.octets() != check {
        return None;
    }
    let y_squared = y.square();
    let numerator = y_squared.sub(&Ed25519Field::ONE);
    let denominator = Ed25519Field::from_octets(&ED25519_CURVE_D)
        .multiply(&y_squared)
        .add(&Ed25519Field::ONE);
    let denominator_squared = denominator.square();
    let denominator_cubed = denominator_squared.multiply(&denominator);
    let denominator_seventh = denominator_cubed.square().multiply(&denominator);
    let mut x = numerator.multiply(&denominator_cubed).multiply(
        &numerator
            .multiply(&denominator_seventh)
            .pow_p_minus_five_over_eight(),
    );
    let candidate = denominator.multiply(&x.square());
    if !candidate.equals(&numerator) {
        if !candidate.equals(&numerator.negate()) {
            return None;
        }
        x = x.multiply(&Ed25519Field::sqrt_minus_one());
    }
    if sign && x.is_zero() {
        return None;
    }
    if x.is_odd() != sign {
        x = x.negate();
    }
    Some(Ed25519Point {
        x,
        y,
        z: Ed25519Field::ONE,
        t: x.multiply(&y),
    })
}

/// Returns whether the presented octets hold exactly one canonical scalar
/// (`GNT-44.3-signature-verification`).
fn ed25519_scalar_is_canonical(scalar: &[u8; 32]) -> bool {
    for index in (0..32).rev() {
        if scalar[index] < ED25519_GROUP_ORDER[index] {
            return true;
        }
        if scalar[index] > ED25519_GROUP_ORDER[index] {
            return false;
        }
    }
    false
}

/// Reduces one wide hash output to the declared scalar range
/// (`GNT-44.3-signature-verification`).
fn ed25519_scalar_reduce(wide: &[u8; 64]) -> [u8; 32] {
    const ORDER_LIMBS: [u64; 4] = [
        0x5812631a5cf5d3ed,
        0x14def9dea2f79cd6,
        0x0000000000000000,
        0x1000000000000000,
    ];
    let mut limbs = [0_u64; 4];
    for bit in (0..512).rev() {
        let mut carry = u64::from((wide[bit / 8] >> (bit % 8)) & 1);
        for limb in &mut limbs {
            let doubled = (*limb << 1) | carry;
            carry = *limb >> 63;
            *limb = doubled;
        }
        let mut at_least = true;
        for index in (0..4).rev() {
            if limbs[index] > ORDER_LIMBS[index] {
                break;
            }
            if limbs[index] < ORDER_LIMBS[index] {
                at_least = false;
                break;
            }
        }
        if at_least {
            let mut borrow = 0_u64;
            for index in 0..4 {
                let (value, first) = limbs[index].overflowing_sub(ORDER_LIMBS[index]);
                let (value, second) = value.overflowing_sub(borrow);
                limbs[index] = value;
                borrow = u64::from(first || second);
            }
        }
    }
    let mut scalar = [0_u8; 32];
    for (index, limb) in limbs.iter().enumerate() {
        scalar[index * 8..index * 8 + 8].copy_from_slice(&limb.to_le_bytes());
    }
    scalar
}

/// Publishes the declared verification verdict of one signature under the declared algorithm of
/// `GNT-44.3-signature-verification`.
///
/// The presentation is admitted in the declared order: the public-key octet count, the signature
/// octet count, the message octet bound, the signature scalar, the public key's point encoding,
/// and the signature's point encoding. A departure from the declared admitted language is refused
/// under `crypto-malformed-input`, a message beyond the declared bound under `crypto-work-limit`,
/// and an admitted presentation publishes exactly one verdict.
pub fn ed25519_verify(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<Ed25519Verdict, CryptoError> {
    if public_key.len() != ED25519_PUBLIC_KEY_OCTET_LENGTH {
        return Err(CryptoError::new(
            CryptoDiagnosticCode::MalformedInput,
            format!(
                "the presented public key holds {} octets; it departs from the declared admitted length at octet {}",
                public_key.len(),
                public_key.len().min(ED25519_PUBLIC_KEY_OCTET_LENGTH)
            ),
        ));
    }
    if signature.len() != ED25519_SIGNATURE_OCTET_LENGTH {
        return Err(CryptoError::new(
            CryptoDiagnosticCode::MalformedInput,
            format!(
                "the presented signature holds {} octets; it departs from the declared admitted length at octet {}",
                signature.len(),
                signature.len().min(ED25519_SIGNATURE_OCTET_LENGTH)
            ),
        ));
    }
    if message.len() > ED25519_MESSAGE_OCTET_BOUND {
        return Err(CryptoError::new(
            CryptoDiagnosticCode::WorkLimit,
            format!(
                "the presented message holds {} octets, beyond the declared bound {ED25519_MESSAGE_OCTET_BOUND}",
                message.len()
            ),
        ));
    }
    let mut key_octets = [0_u8; ED25519_PUBLIC_KEY_OCTET_LENGTH];
    key_octets.copy_from_slice(public_key);
    let mut signature_octets = [0_u8; ED25519_SIGNATURE_OCTET_LENGTH];
    signature_octets.copy_from_slice(signature);
    let mut scalar = [0_u8; 32];
    scalar.copy_from_slice(&signature_octets[32..]);
    if !ed25519_scalar_is_canonical(&scalar) {
        return Err(CryptoError::new(
            CryptoDiagnosticCode::MalformedInput,
            format!(
                "the presented signature scalar is not canonical; it departs from the declared admitted range at signature octet {}",
                ED25519_SIGNATURE_OCTET_LENGTH - 1
            ),
        ));
    }
    let Some(public_point) = ed25519_decode_point(&key_octets) else {
        return Err(CryptoError::new(
            CryptoDiagnosticCode::MalformedInput,
            format!(
                "the presented public key is not a declared curve point; it departs from the declared admitted language at public-key octet {}",
                ED25519_PUBLIC_KEY_OCTET_LENGTH - 1
            ),
        ));
    };
    let mut encoded_r = [0_u8; 32];
    encoded_r.copy_from_slice(&signature_octets[..32]);
    let Some(committed) = ed25519_decode_point(&encoded_r) else {
        return Err(CryptoError::new(
            CryptoDiagnosticCode::MalformedInput,
            format!(
                "the presented signature's committed point is not a declared curve point; it departs from the declared admitted language at signature octet {}",
                31
            ),
        ));
    };
    let mut hashed = Vec::with_capacity(96 + message.len());
    hashed.extend_from_slice(&encoded_r);
    hashed.extend_from_slice(&key_octets);
    hashed.extend_from_slice(message);
    let challenge = ed25519_scalar_reduce(&sha512_digest(&hashed));
    // The declared base point's coordinates are published constants, so the base point is
    // constructed directly rather than recovered from its encoding.
    let (base_x, base_y) = (
        Ed25519Field::from_octets(&ED25519_BASE_POINT_X),
        Ed25519Field::from_octets(&ED25519_BASE_POINT_ENCODED),
    );
    let base = Ed25519Point {
        x: base_x,
        y: base_y,
        z: Ed25519Field::ONE,
        t: base_x.multiply(&base_y),
    };
    let left = base.multiply(&scalar);
    let right = committed.add(&public_point.multiply(&challenge));
    Ok(if left.equals(&right) {
        Ed25519Verdict::Accepted
    } else {
        Ed25519Verdict::Refused
    })
}

/// One declared public item of `std.crypto` (`GNT-34.6-stability-tiers`,
/// `GNT-34.8-defining-identity-and-interface-digest`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CryptoItemRow {
    /// The declared module this item declares.
    pub module: CryptoModule,
    /// The canonical logical item name (`GNT-34.1-canonical-hierarchy-and-package-names`).
    pub name: &'static str,
    /// The declared name classification of `GNT-34.2-name-classification`.
    pub class: NameClass,
    /// The declared stability tier of `GNT-34.6-stability-tiers`.
    pub tier: StabilityTier,
    /// The section clauses this item publishes, in specification order.
    pub clauses: &'static [&'static str],
}

/// The declared public items of `std.crypto`, one module per declared algorithm family.
pub const CRYPTO_ITEMS: [CryptoItemRow; 2] = [
    CryptoItemRow {
        module: CryptoModule::Hash,
        name: "std.crypto::hash",
        class: NameClass::Module,
        tier: StabilityTier::Stable,
        clauses: &[
            "GNT-44.0-crypto-foundation-scope",
            "GNT-44.1-crypto-algorithm-contract",
            "GNT-44.2-content-hashing",
            "GNT-44.4-crypto-non-claims",
        ],
    },
    CryptoItemRow {
        module: CryptoModule::Signature,
        name: "std.crypto::signature",
        class: NameClass::Module,
        tier: StabilityTier::Stable,
        clauses: &[
            "GNT-44.0-crypto-foundation-scope",
            "GNT-44.1-crypto-algorithm-contract",
            "GNT-44.3-signature-verification",
            "GNT-44.4-crypto-non-claims",
        ],
    },
];

/// Declares the published item surface of `std.crypto` over one standard-library graph
/// (`GNT-34.6-stability-tiers`, `GNT-34.8-defining-identity-and-interface-digest`).
pub fn declare_crypto_surface(graph: &mut StdGraph) -> Result<(), StdlibError> {
    let owner = PackageFamily::Crypto.package_name();
    let (modes, targets) = {
        let package = graph.package(&owner).ok_or_else(|| {
            StdlibError::new(
                StdlibDiagnosticCode::UnknownEdge,
                format!("`{owner}` is not declared, so its item surface cannot be declared"),
            )
        })?;
        (
            package.modes().iter().copied().collect::<Vec<_>>(),
            package.targets().iter().copied().collect::<Vec<_>>(),
        )
    };
    for row in CRYPTO_ITEMS {
        graph.declare_item(StdItem::new(
            row.name, row.class, row.tier, &modes, &targets,
        )?)?;
    }
    Ok(())
}

/// Returns the canonical pure hierarchy with the published item surface of `std.crypto` declared
/// (`GNT-34.6-stability-tiers`, `GNT-34.8-defining-identity-and-interface-digest`).
pub fn canonical_crypto_hierarchy() -> Result<StdGraph, StdlibError> {
    let mut graph = crate::stdlib::canonical_pure_hierarchy()?;
    declare_crypto_surface(&mut graph)?;
    Ok(graph)
}
