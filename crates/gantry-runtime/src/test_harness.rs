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

use crate::machine::{Machine, MachineLabel, MachineLimits, MachineStep};

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
}

/// Where one target stopped in a state this entry cannot drive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TestHarnessStop {
    /// The target awaits host dispatch of one prepared operation.
    HostDispatchPending,
    /// The target awaits coordinator-owned child-session creation.
    ChildSessionPending,
}

/// What one admitted target did when the harness executed it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TestTargetOutcome {
    /// The target reached the machine's completion step.
    Completed {
        /// Steps taken, including the completing step.
        steps: u64,
    },
    /// The machine fixed a task-local failure before completion.
    Failed {
        /// Steps taken, including the failing step.
        steps: u64,
    },
    /// The target reached a state this entry cannot drive.
    Undriveable {
        /// Steps taken, including the step that reached the state.
        steps: u64,
        /// The state the harness cannot drive.
        stop: TestHarnessStop,
    },
    /// The target did not complete inside the declared step bound.
    StepBoundExhausted {
        /// Steps taken before the bound was reached.
        steps: u64,
        /// The bound the harness stopped at.
        bound: u64,
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
            targets: BTreeMap::new(),
        }
    }

    /// Admits one target under one declared test name.
    ///
    /// Name refusals reuse the declared discovery vocabulary exactly: an empty name is `Empty` and a
    /// repeated name is `Duplicate`, so the harness admits precisely the sets
    /// `declare_test_discovery` admits. A `DuplicateIdentity` refusal additionally keeps one execution
    /// identity from standing for two targets, because the identity is what the runtime roots a task
    /// in. Nothing is admitted on a refusal.
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
    /// # Errors
    ///
    /// Returns the refusal that applies, leaving the harness unchanged.
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
            let mut machine = Machine::new(
                Arc::clone(&target.program),
                &target.workflow,
                Vec::new(),
                target.execution,
                self.limits,
            )
            .unwrap_or_else(|error| {
                panic!("an admitted target program is a valid machine: {error:?}")
            });
            results.push(TestTargetResult {
                name: name.clone(),
                outcome: execute(&mut machine, bound),
            });
        }
        Ok(TestRunReport { results })
    }
}

/// Steps one machine until it completes, fails, reaches an undriveable state, or exhausts the bound.
fn execute(machine: &mut Machine, bound: u64) -> TestTargetOutcome {
    let mut steps = 0_u64;
    loop {
        if steps >= bound {
            return TestTargetOutcome::StepBoundExhausted { steps, bound };
        }
        steps = steps.saturating_add(1);
        match machine.step() {
            MachineStep::Complete(_) => return TestTargetOutcome::Completed { steps },
            MachineStep::Transition(MachineLabel::Failure(_)) => {
                return TestTargetOutcome::Failed { steps };
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
            MachineStep::Transition(_) | MachineStep::YieldRequired => {}
        }
    }
}
