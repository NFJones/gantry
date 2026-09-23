//! Deterministic execution of admitted `std.test` targets in the runtime harness.
//!
//! This module is the runtime half of the `std.test` contract. The declaration half lives in
//! `gantry_ir::test_support` and publishes the closed test-kind, substitution, execution-rule, and
//! discovery vocabularies plus the declared run plan; this half decides what the runtime does with
//! them. It adds no declaration of its own and publishes no second copy of any declared vocabulary.
//!
//! What the harness owns is execution policy over artifacts its caller presents: which declared kinds
//! this entry can execute, that each executed target gets its own machine and therefore its own
//! budget and state, where a run stops, and how a stop is classified. Each of those is stated below
//! and every one of them is fail-closed: a plan that declares a kind or a substitution this entry does
//! not provide is refused before any machine is constructed, and a target that reaches a state this
//! entry cannot drive is reported as undriveable rather than as a pass.

use std::collections::BTreeMap;
use std::sync::Arc;

use gantry_core::identity::ProtocolIdentity;
use gantry_ir::{CanonicalPath, MachineProgram, TestKind, TestRunPlan, TestSubstitution};

use crate::machine::{
    Machine, MachineBuildError, MachineLabel, MachineLimits, MachineOutcome, MachineStep,
};

/// The declared test kinds this entry executes.
///
/// A unit, integration, or example target is program execution, so this entry can run it. The other
/// declared kinds need machinery this entry does not provide yet - compilation diagnostics for a
/// compile-fail target, snapshot comparison, generation and shrinking for a property target,
/// recorded traces for a replay target, durable cuts for a durable-recovery target, and thresholds
/// for a benchmark target - and each of them is refused by name rather than executed as if it were
/// program execution.
pub const TEST_EXECUTED_KINDS: [TestKind; 3] =
    [TestKind::Unit, TestKind::Integration, TestKind::Example];

/// Why the harness refused a target admission or a declared run plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TestHarnessRefusal {
    /// A declared test name is empty, so it names no target.
    Empty,
    /// A declared test name is already admitted, so one name would name two targets.
    Duplicate,
    /// The presented execution identity is already admitted for another target.
    DuplicateIdentity,
    /// The plan declares a test kind this entry does not execute.
    UnsupportedKind(TestKind),
    /// The plan declares a deterministic substitution this entry does not provide.
    UnsupportedSubstitution(TestSubstitution),
    /// No target is admitted, so the plan has nothing to execute.
    NoTargets,
    /// The declared transition budget is unbounded, so the harness has no finite step bound.
    UnboundedStepBound,
    /// The machine refused to start the presented target, so the target cannot be admitted.
    TargetRejected(MachineBuildError),
}

/// Where one target stopped in a state this entry cannot drive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TestHarnessStop {
    /// The target awaits host dispatch of one prepared operation.
    HostDispatchPending,
    /// The target awaits coordinator-owned child-session creation.
    ///
    /// No public constructor path reaches this state today: `Machine::new` supplies no initial
    /// session, so a non-inline session entry fails its missing-parent check before the machine can
    /// wait for a child session. The branch is classified here so that such a target can never be
    /// reported as a pass if one is ever admitted.
    ChildSessionPending,
}

/// What one admitted target did when the harness executed it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TestTargetOutcome {
    /// The machine fixed a successful outcome for the target.
    Completed {
        /// Labelled transitions the harness observed before it stopped.
        ///
        /// The count includes any terminal bookkeeping labels the machine emits after fixing its
        /// outcome, and it excludes the completing observation itself. The same target can therefore
        /// report different counts at different bounds even though its outcome is fixed at the same
        /// point, which is why the fixed-success regression pins one bound and the ordinary
        /// regression pins another.
        steps: u64,
    },
    /// The machine fixed a task-local failure for the target.
    Failed {
        /// Labelled transitions, including the failing one.
        steps: u64,
    },
    /// The target reached a state this entry cannot drive.
    Undriveable {
        /// Labelled transitions emitted before the state was reached.
        steps: u64,
        /// The state the harness cannot drive.
        stop: TestHarnessStop,
    },
    /// The target did not complete inside the declared step bound.
    StepBoundExhausted {
        /// Labelled transitions taken before the bound was reached.
        steps: u64,
        /// The bound the harness stopped at.
        bound: u64,
    },
    /// The machine fixed a cancellation outcome for the target.
    ///
    /// A cancelled target is never classified as a pass. `steps` is the labelled transitions observed
    /// when the cancellation was presented - the harness bound - and `reason` is the reason the
    /// machine fixed, which a cancelled machine keeps as its first reason.
    Cancelled {
        /// Labelled transitions observed when the cancellation was presented.
        steps: u64,
        /// The first cancellation reason the machine fixed.
        reason: Arc<str>,
    },
}

/// One admitted target and what it did.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestTargetResult {
    name: String,
    outcome: TestTargetOutcome,
}

impl TestTargetResult {
    /// Returns the declared test name of this result.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns what the target did.
    #[must_use]
    pub const fn outcome(&self) -> &TestTargetOutcome {
        &self.outcome
    }
}

/// What one declared run plan did over the admitted targets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestRunReport {
    results: Vec<TestTargetResult>,
}

impl TestRunReport {
    /// Returns one result per admitted target, in canonical target-name order.
    #[must_use]
    pub fn results(&self) -> &[TestTargetResult] {
        &self.results
    }

    /// Returns whether every admitted target completed, which is the only clean report.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.results
            .iter()
            .all(|result| matches!(result.outcome, TestTargetOutcome::Completed { .. }))
    }
}

/// One admitted test target: the program that implements it and the identity layer's execution.
#[derive(Clone, Debug)]
struct AdmittedTestTarget {
    program: Arc<MachineProgram>,
    workflow: CanonicalPath,
    execution: ProtocolIdentity,
}

/// The runtime test harness: admitted targets, their machine limits, and their step bound.
///
/// A harness is replayable and pure with respect to its inputs: it holds no ambient authority, reads
/// no clock, and constructs a fresh machine for every target it executes, so two runs of one plan over
/// one harness produce the same report and one target's steps, budget, or outcome are never shared
/// with another.
#[derive(Clone, Debug)]
pub struct TestHarness {
    limits: MachineLimits,
    cancel_at_bound: Option<Arc<str>>,
    targets: BTreeMap<String, AdmittedTestTarget>,
}

impl TestHarness {
    /// Creates an empty harness whose targets run under the machine limits it is given.
    ///
    /// The declared transition budget of those limits is also the harness's step bound: a target that
    /// has not completed within it is reported as `StepBoundExhausted`, so a run can never spin past
    /// the budget the caller declared for it.
    #[must_use]
    pub fn new(limits: MachineLimits) -> Self {
        Self {
            limits,
            cancel_at_bound: None,
            targets: BTreeMap::new(),
        }
    }

    /// Declares that this harness cancels a target that reaches its bound, under one reason.
    ///
    /// A harness that declares a cancellation reason turns its bound into a timeout with cleanup:
    /// when a target reaches the bound without a fixed outcome, the harness presents the declared
    /// reason, settles the cancellation the machine fixes, and reports `Cancelled` with that reason
    /// rather than reporting exhaustion. The reason is the caller's, exactly as the target's program
    /// and execution identity are, so the harness invents no cancellation vocabulary of its own. A
    /// harness that declares no reason keeps stopping at the bound and reports `StepBoundExhausted`.
    #[must_use]
    pub fn with_cancellation(mut self, reason: Arc<str>) -> Self {
        self.cancel_at_bound = Some(reason);
        self
    }

    /// Admits one target under one declared test name.
    ///
    /// Name refusals reuse the declared discovery vocabulary exactly: an empty name is `Empty` and a
    /// repeated name is `Duplicate`, so the harness admits precisely the sets
    /// `declare_test_discovery` admits. A `DuplicateIdentity` refusal additionally keeps one execution
    /// identity from standing for two targets, because the identity is what the runtime roots a task
    /// in. The target is then validated by constructing the machine it would run in: a program whose
    /// root the presented workflow does not name, an argument or identity the machine refuses, or an
    /// effect it does not support is refused here as `TargetRejected` rather than stored and failing
    /// later, so every admitted target is one the machine accepts. Nothing is admitted on a refusal.
    pub fn admit(
        &mut self,
        name: &str,
        program: Arc<MachineProgram>,
        workflow: CanonicalPath,
        execution: ProtocolIdentity,
    ) -> Result<(), TestHarnessRefusal> {
        if name.is_empty() {
            return Err(TestHarnessRefusal::Empty);
        }
        if self.targets.contains_key(name) {
            return Err(TestHarnessRefusal::Duplicate);
        }
        if self
            .targets
            .values()
            .any(|target| target.execution == execution)
        {
            return Err(TestHarnessRefusal::DuplicateIdentity);
        }
        if let Err(error) = Machine::new(
            Arc::clone(&program),
            &workflow,
            Vec::new(),
            execution,
            self.limits,
        ) {
            return Err(TestHarnessRefusal::TargetRejected(error));
        }
        self.targets.insert(
            name.to_owned(),
            AdmittedTestTarget {
                program,
                workflow,
                execution,
            },
        );
        Ok(())
    }

    /// Returns the admitted target names in canonical discovery order.
    #[must_use]
    pub fn admitted(&self) -> Vec<&str> {
        self.targets.keys().map(String::as_str).collect()
    }

    /// Returns the machine limits admitted targets run under.
    #[must_use]
    pub const fn limits(&self) -> &MachineLimits {
        &self.limits
    }

    /// Executes one declared run plan over the admitted targets.
    ///
    /// The plan is checked before any machine exists: a declared kind outside
    /// [`TEST_EXECUTED_KINDS`] is refused as `UnsupportedKind` and a declared substitution is refused
    /// as `UnsupportedSubstitution`, because this entry provides no substitution machinery. An empty
    /// harness is refused as `NoTargets`. Otherwise every admitted target runs, in canonical
    /// name order, each in its own machine and under the harness's step bound.
    ///
    /// The step bound is the machine's declared transition budget, counted in labelled transitions.
    /// A cooperative yield is not a labelled transition: the machine is resumed and the bound counts
    /// the yields too, so a machine that yields without ever transitioning still cannot spin. A
    /// completion or a fixed machine outcome is never lost to the bound: when the bound is reached,
    /// an outcome the machine has already fixed is reported as `Completed`, `Failed`, or `Cancelled`
    /// instead of as exhaustion, and only a target with no fixed outcome is reported exhausted.
    ///
    /// # Errors
    ///
    /// Returns the refusal that applies, leaving the harness unchanged. The construction branch is
    /// unreachable for an admitted target - `admit` validated the same construction - and exists so
    /// that a caller can never panic a run.
    pub fn run(&self, plan: &TestRunPlan) -> Result<TestRunReport, TestHarnessRefusal> {
        for kind in plan.kinds() {
            if !TEST_EXECUTED_KINDS.contains(kind) {
                return Err(TestHarnessRefusal::UnsupportedKind(*kind));
            }
        }
        if let Some(substitution) = plan.substitutions().first() {
            return Err(TestHarnessRefusal::UnsupportedSubstitution(*substitution));
        }
        if self.targets.is_empty() {
            return Err(TestHarnessRefusal::NoTargets);
        }
        let Some(bound) = self.limits.maximum_deterministic_transitions.maximum() else {
            return Err(TestHarnessRefusal::UnboundedStepBound);
        };
        let mut results = Vec::with_capacity(self.targets.len());
        for (name, target) in &self.targets {
            let mut machine = match Machine::new(
                Arc::clone(&target.program),
                &target.workflow,
                Vec::new(),
                target.execution,
                self.limits,
            ) {
                Ok(machine) => machine,
                Err(error) => return Err(TestHarnessRefusal::TargetRejected(error)),
            };
            results.push(TestTargetResult {
                name: name.clone(),
                outcome: execute(&mut machine, bound, self.cancel_at_bound.as_ref()),
            });
        }
        Ok(TestRunReport { results })
    }
}

/// Steps one machine until it completes, fails, is cancelled, reaches an undriveable state, or
/// exhausts the bound.
///
/// Labelled transitions - every `Transition` label, including a failure - are counted against the
/// bound. A cooperative yield is resumed rather than counted as progress, and yields carry their own
/// ceiling so a machine that never transitions still cannot spin. Reaching the bound is decided by
/// the outcome the machine has already fixed, when it has fixed one: a completed, failed, or
/// cancelled target is never reported as exhaustion.
fn execute(
    machine: &mut Machine,
    bound: u64,
    cancel_at_bound: Option<&Arc<str>>,
) -> TestTargetOutcome {
    let mut labelled = 0_u64;
    let mut yields = 0_u64;
    loop {
        if labelled >= bound {
            if let Some(reason) = cancel_at_bound
                && machine.outcome().is_none()
            {
                let _label = machine.cancel(Arc::clone(reason));
                return drain_cancellation(machine, labelled, bound);
            }
            return bound_outcome(machine, labelled, bound);
        }
        match machine.step() {
            MachineStep::Complete(outcome) => return classify(&outcome, labelled),
            MachineStep::Transition(MachineLabel::Failure(_)) => {
                return TestTargetOutcome::Failed {
                    steps: labelled.saturating_add(1),
                };
            }
            MachineStep::Transition(_) => labelled = labelled.saturating_add(1),
            MachineStep::WaitingOperation(_) => {
                return TestTargetOutcome::Undriveable {
                    steps: labelled,
                    stop: TestHarnessStop::HostDispatchPending,
                };
            }
            MachineStep::WaitingSessionScope(_) => {
                return TestTargetOutcome::Undriveable {
                    steps: labelled,
                    stop: TestHarnessStop::ChildSessionPending,
                };
            }
            MachineStep::YieldRequired => {
                yields = yields.saturating_add(1);
                if yields > bound {
                    return bound_outcome(machine, labelled, bound);
                }
                let _resumed = machine.resume_after_yield();
            }
        }
    }
}

/// Classifies one fixed machine outcome for the harness.
fn classify(outcome: &MachineOutcome, steps: u64) -> TestTargetOutcome {
    match outcome {
        MachineOutcome::Succeeded(_) => TestTargetOutcome::Completed { steps },
        MachineOutcome::Failed(_) => TestTargetOutcome::Failed { steps },
        MachineOutcome::Cancelled(reason) => TestTargetOutcome::Cancelled {
            steps,
            reason: Arc::clone(reason),
        },
    }
}

/// Settles one presented cancellation and reports the reason the machine fixed.
///
/// The settle loop has its own ceiling equal to the harness bound, so a cancellation that never
/// settles cannot spin; when that ceiling is reached the target is classified by whatever the machine
/// has already fixed, exactly as the bound classifier does.
fn drain_cancellation(machine: &mut Machine, steps: u64, bound: u64) -> TestTargetOutcome {
    let mut observations = 0_u64;
    loop {
        if observations >= bound {
            return bound_outcome(machine, steps, bound);
        }
        observations = observations.saturating_add(1);
        match machine.step() {
            MachineStep::Complete(outcome) => return classify(&outcome, steps),
            MachineStep::YieldRequired => {
                let _resumed = machine.resume_after_yield();
            }
            MachineStep::WaitingOperation(_) => {
                return TestTargetOutcome::Undriveable {
                    steps,
                    stop: TestHarnessStop::HostDispatchPending,
                };
            }
            MachineStep::WaitingSessionScope(_) => {
                return TestTargetOutcome::Undriveable {
                    steps,
                    stop: TestHarnessStop::ChildSessionPending,
                };
            }
            MachineStep::Transition(_) => {}
        }
    }
}

/// Classifies a target that reached the harness bound by whatever the machine already fixed.
fn bound_outcome(machine: &Machine, steps: u64, bound: u64) -> TestTargetOutcome {
    match machine.outcome() {
        Some(outcome) => classify(outcome, steps),
        None => TestTargetOutcome::StepBoundExhausted { steps, bound },
    }
}
