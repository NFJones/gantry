//! Pure callable-value, capture, reuse, and frame-admission contract.
//!
//! Gantry v1 admits no callable type: `GNT-3-T-GENERIC-CALL` states that
//! closure types remain unadmitted, so no v1 profile computes a callable row
//! and the callable-row composition rules of `GNT-3-T-EFFECTS` are vacuous in
//! this revision. This module is the analyzer-side substrate for the admission
//! owned by `GNT-GP-CLOSURE-001`: it defines the reuse-kind vocabulary, capture
//! descriptors, plans and modes, bounded shape, name, capture, and logical-frame
//! budgets, admission and settlement transitions, closed effect rows, an
//! injective length-prefixed canonical identity, and the durable capture
//! projection.
//!
//! It defines no source syntax, no runtime representation or native frame
//! layout, no dynamic dispatch, no trait solving, and no ambient capture, and it
//! admits no callable type into any analyzed, executable, or durable artifact:
//! adding this module changes no v1 behavior and no published evidence.

use std::collections::BTreeMap;
use std::fmt;

use crate::effects::{EFFECT_ORDER, EffectSet};
use crate::generated::Effect;

/// Canonical tag carried by every callable encoding.
const CALLABLE_TAG: &str = "gantry-callable-v1";

/// One admitted callable reuse kind.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CallableKind {
    /// Reusable callable whose captures are observed immutably.
    Function,
    /// Reusable callable that holds exclusive capture access per live call.
    FunctionMut,
    /// Single-use callable consumed by its first admitted call.
    FunctionOnce,
}

impl CallableKind {
    /// Every reuse kind in normative order.
    pub const ALL: [Self; 3] = [Self::Function, Self::FunctionMut, Self::FunctionOnce];

    /// Returns the canonical source spelling.
    #[must_use]
    pub const fn canonical_name(self) -> &'static str {
        match self {
            Self::Function => "Fn",
            Self::FunctionMut => "FnMut",
            Self::FunctionOnce => "FnOnce",
        }
    }

    /// Returns the reuse kind of one canonical spelling.
    pub fn from_canonical_name(name: &str) -> Result<Self, CallableError> {
        Self::ALL
            .into_iter()
            .find(|kind| kind.canonical_name() == name)
            .ok_or_else(|| shape(format!("`{name}` is not an admitted callable reuse kind")))
    }

    /// Returns whether two live calls of this kind may overlap.
    #[must_use]
    pub const fn admits_overlapping_calls(self) -> bool {
        matches!(self, Self::Function)
    }

    /// Returns whether one admitted call consumes the value.
    #[must_use]
    pub const fn consumes_on_admission(self) -> bool {
        matches!(self, Self::FunctionOnce)
    }

    /// Returns whether one live call holds exclusive capture access.
    #[must_use]
    pub const fn requires_exclusive_access(self) -> bool {
        !self.admits_overlapping_calls()
    }
}

impl fmt::Display for CallableKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.canonical_name())
    }
}

/// One capture mode of a callable's environment.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CaptureMode {
    /// Copied snapshot of a copied binding.
    Copy,
    /// Owned transfer of the captured binding into the callable.
    Move,
    /// Exclusive loan of an outer binding for the callable's live extent.
    Loan,
}

impl CaptureMode {
    /// Every capture mode in normative order.
    pub const ALL: [Self; 3] = [Self::Copy, Self::Move, Self::Loan];

    /// Returns the canonical spelling.
    #[must_use]
    pub const fn canonical_name(self) -> &'static str {
        match self {
            Self::Copy => "copy",
            Self::Move => "move",
            Self::Loan => "loan",
        }
    }

    /// Returns the capture mode of one canonical spelling.
    pub fn from_canonical_name(name: &str) -> Result<Self, CallableError> {
        Self::ALL
            .into_iter()
            .find(|mode| mode.canonical_name() == name)
            .ok_or_else(|| shape(format!("`{name}` is not an admitted capture mode")))
    }

    /// Returns whether the mode may appear in a durable capture projection.
    #[must_use]
    pub const fn is_durable(self) -> bool {
        !matches!(self, Self::Loan)
    }

    /// Returns whether the mode transfers ownership of the captured binding.
    #[must_use]
    pub const fn transfers_ownership(self) -> bool {
        matches!(self, Self::Move)
    }
}

impl fmt::Display for CaptureMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.canonical_name())
    }
}

/// One bounded admission budget for callable values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CallableLimits {
    /// Maximum declared parameters of one callable.
    pub max_parameters: usize,
    /// Maximum declared captures of one callable.
    pub max_captures: usize,
    /// Maximum bytes in one declared parameter, result, or capture name.
    pub max_name_bytes: usize,
    /// Maximum live logical callable frames.
    pub max_frames: usize,
}

impl Default for CallableLimits {
    fn default() -> Self {
        Self {
            max_parameters: 32,
            max_captures: 64,
            max_name_bytes: 256,
            max_frames: 64,
        }
    }
}

/// One frozen callable refusal condition.
///
/// Each spelling owns exactly one condition: declared shape, name, and budget
/// departures are `ShapeRefused`; an inadmissible capture plan is
/// `CaptureRefused`; a reuse kind refusing an admission is `ReuseRefused`; a
/// logical-frame budget departure is `FrameLimit`; a settlement matching no
/// outstanding admission is `SettlementRefused`; a declared row erasing a
/// component effect is `EffectErasure`; an ineligible durable projection is
/// `DurableCapture`; and a rebuilt projection unequal to its carried identity is
/// `RoundTripLoss`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CallableDiagnosticCode {
    /// A declared shape, name, or budget departure.
    ShapeRefused,
    /// An inadmissible capture plan.
    CaptureRefused,
    /// A reuse kind refusing the requested admission.
    ReuseRefused,
    /// A logical-frame budget departure.
    FrameLimit,
    /// A settlement matching no outstanding admission.
    SettlementRefused,
    /// A declared row erasing a component effect.
    EffectErasure,
    /// An ineligible durable capture projection.
    DurableCapture,
    /// A rebuilt projection unequal to its carried identity.
    RoundTripLoss,
}

impl CallableDiagnosticCode {
    /// Every refusal condition in normative order.
    pub const ALL: [Self; 8] = [
        Self::ShapeRefused,
        Self::CaptureRefused,
        Self::ReuseRefused,
        Self::FrameLimit,
        Self::SettlementRefused,
        Self::EffectErasure,
        Self::DurableCapture,
        Self::RoundTripLoss,
    ];

    /// Returns the frozen diagnostic spelling.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ShapeRefused => "callable-shape-refused",
            Self::CaptureRefused => "callable-capture-refused",
            Self::ReuseRefused => "callable-reuse-refused",
            Self::FrameLimit => "callable-frame-limit",
            Self::SettlementRefused => "callable-settlement-refused",
            Self::EffectErasure => "callable-effect-erasure",
            Self::DurableCapture => "callable-durable-capture",
            Self::RoundTripLoss => "callable-round-trip-loss",
        }
    }
}

impl fmt::Display for CallableDiagnosticCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

/// One callable refusal with its owning condition and bounded detail.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallableError {
    code: CallableDiagnosticCode,
    detail: String,
}

impl CallableError {
    fn new(code: CallableDiagnosticCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    /// Returns the owning refusal condition.
    #[must_use]
    pub const fn code(&self) -> CallableDiagnosticCode {
        self.code
    }

    /// Returns the refusal detail.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for CallableError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for CallableError {}

fn shape(detail: impl Into<String>) -> CallableError {
    CallableError::new(CallableDiagnosticCode::ShapeRefused, detail)
}

fn capture(detail: impl Into<String>) -> CallableError {
    CallableError::new(CallableDiagnosticCode::CaptureRefused, detail)
}

fn reuse(detail: impl Into<String>) -> CallableError {
    CallableError::new(CallableDiagnosticCode::ReuseRefused, detail)
}

fn frame_limit(detail: impl Into<String>) -> CallableError {
    CallableError::new(CallableDiagnosticCode::FrameLimit, detail)
}

fn settlement(detail: impl Into<String>) -> CallableError {
    CallableError::new(CallableDiagnosticCode::SettlementRefused, detail)
}

fn effect_erasure(detail: impl Into<String>) -> CallableError {
    CallableError::new(CallableDiagnosticCode::EffectErasure, detail)
}

fn durable_capture(detail: impl Into<String>) -> CallableError {
    CallableError::new(CallableDiagnosticCode::DurableCapture, detail)
}

fn round_trip(detail: impl Into<String>) -> CallableError {
    CallableError::new(CallableDiagnosticCode::RoundTripLoss, detail)
}

/// Appends one length-prefixed component to a canonical encoding.
fn push_component(encoded: &mut String, text: &str) {
    encoded.push_str(&text.len().to_string());
    encoded.push(':');
    encoded.push_str(text);
}

/// Returns the normative index of one effect.
fn effect_index(effect: Effect) -> usize {
    EFFECT_ORDER
        .iter()
        .position(|candidate| *candidate == effect)
        .unwrap_or(usize::MAX)
}

/// Returns the union of declared component rows.
///
/// Union is the only composition: no component may be narrowed, intersected,
/// or discharged, and the result is independent of component order.
#[must_use]
pub fn union_row(components: &[EffectSet]) -> EffectSet {
    components
        .iter()
        .fold(EffectSet::default(), |row, component| row.union(*component))
}

/// One declared capture of a callable's environment.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CaptureDescriptor {
    name: String,
    mode: CaptureMode,
}

impl CaptureDescriptor {
    /// Declares one capture, refusing an unnamed or over-budget binding.
    pub fn new(
        name: &str,
        mode: CaptureMode,
        limits: CallableLimits,
    ) -> Result<Self, CallableError> {
        if name.is_empty() {
            return Err(capture("a capture names exactly one binding"));
        }
        if name.len() > limits.max_name_bytes {
            return Err(shape(format!(
                "capture name of {} bytes exceeds {}",
                name.len(),
                limits.max_name_bytes
            )));
        }
        Ok(Self {
            name: name.to_owned(),
            mode,
        })
    }

    /// Returns the captured binding name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the capture mode.
    #[must_use]
    pub const fn mode(&self) -> CaptureMode {
        self.mode
    }

    /// Returns the length-prefixed encoding of this capture.
    #[must_use]
    pub fn canonical_encoding(&self) -> String {
        let mut encoded = String::new();
        push_component(&mut encoded, &self.name);
        push_component(&mut encoded, self.mode.canonical_name());
        encoded
    }
}

/// One canonical capture plan: every captured binding at most once, ordered by
/// binding name so declaration order is never semantic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturePlan {
    captures: Vec<CaptureDescriptor>,
}

impl CapturePlan {
    /// Builds one plan, refusing duplicate bindings and over-budget plans.
    pub fn new(
        captures: Vec<CaptureDescriptor>,
        limits: CallableLimits,
    ) -> Result<Self, CallableError> {
        if captures.len() > limits.max_captures {
            return Err(shape(format!(
                "{} captures exceed {}",
                captures.len(),
                limits.max_captures
            )));
        }
        let mut ordered = captures;
        ordered.sort_by(|left, right| left.name.cmp(&right.name));
        for pair in ordered.windows(2) {
            if pair[0].name == pair[1].name {
                return Err(capture(format!("`{}` is captured twice", pair[0].name)));
            }
        }
        Ok(Self { captures: ordered })
    }

    /// Returns the declared captures in canonical order.
    #[must_use]
    pub fn captures(&self) -> &[CaptureDescriptor] {
        &self.captures
    }

    /// Returns whether the plan declares no capture.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.captures.is_empty()
    }

    /// Returns whether every declared capture mode is durable.
    #[must_use]
    pub fn is_durable(&self) -> bool {
        self.captures
            .iter()
            .all(|capture| capture.mode.is_durable())
    }

    /// Returns the length-prefixed encoding of this plan.
    #[must_use]
    pub fn canonical_encoding(&self) -> String {
        let mut encoded = String::new();
        push_component(&mut encoded, &self.captures.len().to_string());
        for capture in &self.captures {
            encoded.push_str(&capture.canonical_encoding());
        }
        encoded
    }
}

/// One reuse state of a callable value.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReuseState {
    /// Admits a new call under this kind's rules.
    Live,
    /// Consumed by one admitted single-use call.
    Consumed,
    /// Refuses reuse after an unsettled exclusive call.
    Poisoned,
}

impl ReuseState {
    /// Returns the canonical spelling.
    #[must_use]
    pub const fn canonical_name(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Consumed => "consumed",
            Self::Poisoned => "poisoned",
        }
    }
}

impl fmt::Display for ReuseState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.canonical_name())
    }
}

/// One settlement outcome of an admitted call.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CallSettlement {
    /// The call returned normally.
    Completed,
    /// The call returned one typed domain error.
    DomainError,
    /// The call failed operationally.
    Failed,
    /// The call was cancelled before settlement.
    Cancelled,
}

impl CallSettlement {
    /// Returns whether the outcome leaves exclusive capture state unsettled.
    #[must_use]
    pub const fn poisons_exclusive_state(self) -> bool {
        matches!(self, Self::Failed | Self::Cancelled)
    }

    /// Returns the canonical spelling.
    #[must_use]
    pub const fn canonical_name(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::DomainError => "domain-error",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

/// One outstanding call admission that must settle exactly once.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CallAdmission {
    id: u64,
    depth: usize,
}

impl CallAdmission {
    const fn new(id: u64, depth: usize) -> Self {
        Self { id, depth }
    }

    /// Returns the admission identity.
    #[must_use]
    pub const fn id(self) -> u64 {
        self.id
    }

    /// Returns the logical frame depth this admission was granted at.
    #[must_use]
    pub const fn depth(self) -> usize {
        self.depth
    }
}

/// One callable value: reuse kind, declared shape, capture plan, declared row,
/// and reuse state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallableValue {
    kind: CallableKind,
    parameters: Vec<String>,
    result: String,
    captures: CapturePlan,
    row: EffectSet,
    state: ReuseState,
    active: BTreeMap<u64, usize>,
    issued: u64,
}

impl CallableValue {
    /// Declares one callable value, refusing over-budget shape departures.
    pub fn new(
        kind: CallableKind,
        parameters: Vec<String>,
        result: &str,
        captures: CapturePlan,
        row: EffectSet,
        limits: CallableLimits,
    ) -> Result<Self, CallableError> {
        if parameters.len() > limits.max_parameters {
            return Err(shape(format!(
                "{} parameters exceed {}",
                parameters.len(),
                limits.max_parameters
            )));
        }
        for parameter in &parameters {
            if parameter.is_empty() {
                return Err(shape("a parameter names exactly one type"));
            }
            if parameter.len() > limits.max_name_bytes {
                return Err(shape(format!(
                    "parameter of {} bytes exceeds {}",
                    parameter.len(),
                    limits.max_name_bytes
                )));
            }
        }
        if result.is_empty() {
            return Err(shape("a callable declares exactly one result type"));
        }
        if result.len() > limits.max_name_bytes {
            return Err(shape(format!(
                "result of {} bytes exceeds {}",
                result.len(),
                limits.max_name_bytes
            )));
        }
        Ok(Self {
            kind,
            parameters,
            result: result.to_owned(),
            captures,
            row,
            state: ReuseState::Live,
            active: BTreeMap::new(),
            issued: 0,
        })
    }

    /// Returns the reuse kind.
    #[must_use]
    pub const fn kind(&self) -> CallableKind {
        self.kind
    }

    /// Returns the declared parameter types in declaration order.
    #[must_use]
    pub fn parameters(&self) -> &[String] {
        &self.parameters
    }

    /// Returns the declared result type.
    #[must_use]
    pub fn result(&self) -> &str {
        &self.result
    }

    /// Returns the canonical capture plan.
    #[must_use]
    pub const fn captures(&self) -> &CapturePlan {
        &self.captures
    }

    /// Returns the declared effect row.
    #[must_use]
    pub const fn row(&self) -> EffectSet {
        self.row
    }

    /// Returns the reuse state.
    #[must_use]
    pub const fn state(&self) -> ReuseState {
        self.state
    }

    /// Returns the number of live calls.
    #[must_use]
    pub fn live_calls(&self) -> usize {
        self.active.len()
    }

    /// Admits one call at a logical frame depth.
    ///
    /// A consumed or poisoned value refuses reuse; a kind that holds exclusive
    /// capture access refuses an overlapping admission; a single-use kind is
    /// consumed at admission; and a depth at or beyond the declared budget is
    /// refused before any charge.
    pub fn admit(
        &mut self,
        depth: usize,
        limits: CallableLimits,
    ) -> Result<CallAdmission, CallableError> {
        match self.state {
            ReuseState::Consumed => {
                return Err(reuse(format!("{} value is consumed", self.kind)));
            }
            ReuseState::Poisoned => {
                return Err(reuse(format!("{} value is poisoned", self.kind)));
            }
            ReuseState::Live => {}
        }
        if depth >= limits.max_frames {
            return Err(frame_limit(format!(
                "logical frame depth {depth} exceeds {}",
                limits.max_frames
            )));
        }
        if self.kind.requires_exclusive_access() && !self.active.is_empty() {
            return Err(reuse(format!(
                "{} value already has a live call",
                self.kind
            )));
        }
        if self.kind.consumes_on_admission() {
            self.state = ReuseState::Consumed;
        }
        let id = self.issued;
        self.issued += 1;
        self.active.insert(id, depth);
        Ok(CallAdmission::new(id, depth))
    }

    /// Settles one outstanding admission exactly once.
    ///
    /// A completed or typed-domain-error settlement leaves a reusable kind
    /// reusable; a failed or cancelled settlement poisons a kind that holds
    /// exclusive capture state, because that state may be partially settled,
    /// while an immutable-capture kind remains reusable.
    pub fn settle(
        &mut self,
        admission: CallAdmission,
        outcome: CallSettlement,
    ) -> Result<(), CallableError> {
        if self.active.remove(&admission.id()).is_none() {
            return Err(settlement(format!(
                "admission {} is not outstanding",
                admission.id()
            )));
        }
        if outcome.poisons_exclusive_state() && self.kind.requires_exclusive_access() {
            self.state = ReuseState::Poisoned;
        }
        Ok(())
    }

    /// Returns whether the declared row contains every component effect.
    #[must_use]
    pub fn row_is_closed(&self, components: &[EffectSet]) -> bool {
        union_row(components)
            .iter()
            .all(|effect| self.row.contains(effect))
    }

    /// Requires the declared row to contain every component effect.
    pub fn require_closed_row(&self, components: &[EffectSet]) -> Result<(), CallableError> {
        for effect in union_row(components).iter() {
            if !self.row.contains(effect) {
                return Err(effect_erasure(format!(
                    "declared row omits effect index {}",
                    effect_index(effect)
                )));
            }
        }
        Ok(())
    }

    /// Returns the length-prefixed canonical encoding of this value.
    ///
    /// Every component is length-prefixed, so two values with different
    /// spellings never share one encoding, and capture order is canonical rather
    /// than declared.
    #[must_use]
    pub fn canonical_encoding(&self) -> String {
        let mut encoded = String::new();
        push_component(&mut encoded, CALLABLE_TAG);
        push_component(&mut encoded, self.kind.canonical_name());
        push_component(&mut encoded, &self.parameters.len().to_string());
        for parameter in &self.parameters {
            push_component(&mut encoded, parameter);
        }
        push_component(&mut encoded, &self.result);
        encoded.push_str(&self.captures.canonical_encoding());
        let effects: Vec<String> = self
            .row
            .iter()
            .map(|effect| effect_index(effect).to_string())
            .collect();
        push_component(&mut encoded, &effects.len().to_string());
        for effect in effects {
            push_component(&mut encoded, &effect);
        }
        encoded
    }

    /// Returns the durable capture projection of a durable-eligible value.
    ///
    /// A value with a live call, a consumed or poisoned reuse state, or a loan
    /// capture is refused rather than partially projected.
    pub fn durable_projection(&self) -> Result<CallableProjection, CallableError> {
        if !self.active.is_empty() {
            return Err(durable_capture(format!(
                "{} live call(s) are not durable",
                self.active.len()
            )));
        }
        if self.state != ReuseState::Live {
            return Err(durable_capture(format!(
                "a {} callable carries no durable reuse state",
                self.state
            )));
        }
        for capture in self.captures.captures() {
            if !capture.mode().is_durable() {
                return Err(durable_capture(format!(
                    "capture `{}` is a loan and is not durable",
                    capture.name()
                )));
            }
        }
        Ok(CallableProjection {
            kind: self.kind,
            parameters: self.parameters.clone(),
            result: self.result.clone(),
            captures: self
                .captures
                .captures()
                .iter()
                .map(|capture| (capture.name().to_owned(), capture.mode()))
                .collect(),
            row: self.row,
            identity: self.canonical_encoding(),
        })
    }

    /// Requires one projection to carry this value's canonical encoding.
    pub fn require_round_trip(&self, projection: &CallableProjection) -> Result<(), CallableError> {
        if self.canonical_encoding() != projection.identity() {
            return Err(round_trip(
                "the carried projection is not this value's canonical encoding",
            ));
        }
        Ok(())
    }
}

/// One durable capture projection of a callable value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallableProjection {
    kind: CallableKind,
    parameters: Vec<String>,
    result: String,
    captures: Vec<(String, CaptureMode)>,
    row: EffectSet,
    identity: String,
}

impl CallableProjection {
    /// Returns the carried reuse kind.
    #[must_use]
    pub const fn kind(&self) -> CallableKind {
        self.kind
    }

    /// Returns the carried parameter types.
    #[must_use]
    pub fn parameters(&self) -> &[String] {
        &self.parameters
    }

    /// Returns the carried result type.
    #[must_use]
    pub fn result(&self) -> &str {
        &self.result
    }

    /// Returns the carried captures in canonical order.
    #[must_use]
    pub fn captures(&self) -> &[(String, CaptureMode)] {
        &self.captures
    }

    /// Returns the carried row.
    #[must_use]
    pub const fn row(&self) -> EffectSet {
        self.row
    }

    /// Returns the carried canonical identity.
    #[must_use]
    pub fn identity(&self) -> &str {
        &self.identity
    }

    /// Reconstructs one carried projection from durable components.
    ///
    /// The carried identity is not recomputed here: a rebuild compares the
    /// recomputed canonical encoding with the carried one and refuses the
    /// projection under the round-trip-loss condition when they differ.
    #[must_use]
    pub fn carried(
        kind: CallableKind,
        parameters: Vec<String>,
        result: &str,
        captures: Vec<(String, CaptureMode)>,
        row: EffectSet,
        identity: &str,
    ) -> Self {
        Self {
            kind,
            parameters,
            result: result.to_owned(),
            captures,
            row,
            identity: identity.to_owned(),
        }
    }

    /// Rebuilds one live value, refusing a projection that no longer encodes
    /// the identity it carries.
    pub fn rebuild(&self, limits: CallableLimits) -> Result<CallableValue, CallableError> {
        let declared: Result<Vec<CaptureDescriptor>, CallableError> = self
            .captures
            .iter()
            .map(|(name, mode)| CaptureDescriptor::new(name, *mode, limits))
            .collect();
        let captures = CapturePlan::new(declared?, limits)?;
        let value = CallableValue::new(
            self.kind,
            self.parameters.clone(),
            &self.result,
            captures,
            self.row,
            limits,
        )?;
        if value.canonical_encoding() != self.identity {
            return Err(round_trip(
                "the rebuilt value does not encode the carried identity",
            ));
        }
        Ok(value)
    }
}
