//! Pipeline StateGraph & Software Factory Station State Machine.
//!
//! Enforces validated state transitions across the 6 formal software factory stations:
//! 1. Recon (Station 1: Target fingerprinting, dynamic directives & boundary synthesis)
//! 2. Discovery (Station 2: Endpoint discovery, semantic route prediction)
//! 3. Plan (Station 3: Attack DAG, dynamic case synthesis)
//! 4. Execute (Station 4: Execution & adaptive ReAct feedback loop)
//! 5. Verify (Station 5: Independent replay & Contextual Taint Tracing Juror)
//! 6. Gate (Station 6: Factory Attestation, release readiness scoring & ASVS compliance)

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Discrete states of the autonomous software factory pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PipelineState {
    Recon,
    Discovery,
    Plan,
    Execute,
    Verify,
    Gate,
    Completed,
    Failed,
}

impl PipelineState {
    /// Human-readable station name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Recon => "Recon",
            Self::Discovery => "Discovery",
            Self::Plan => "Plan",
            Self::Execute => "Execute",
            Self::Verify => "Verify",
            Self::Gate => "Gate",
            Self::Completed => "Completed",
            Self::Failed => "Failed",
        }
    }

    /// Station order number (1 to 6, or 0 for terminal).
    pub fn station_index(&self) -> usize {
        match self {
            Self::Recon => 1,
            Self::Discovery => 2,
            Self::Plan => 3,
            Self::Execute => 4,
            Self::Verify => 5,
            Self::Gate => 6,
            Self::Completed | Self::Failed => 0,
        }
    }

    /// Check whether a transition from `self` to `target` is allowed.
    pub fn can_transition_to(&self, target: PipelineState) -> bool {
        match (self, target) {
            // Forward progression through the 6 formal stations
            (Self::Recon, Self::Discovery) => true,
            (Self::Discovery, Self::Plan) => true,
            (Self::Plan, Self::Execute) => true,
            (Self::Execute, Self::Verify) => true,
            (Self::Verify, Self::Gate) => true,
            (Self::Gate, Self::Completed) => true,

            // Self-loops and adaptive refinements within stations
            (Self::Recon, Self::Recon) => true,
            (Self::Discovery, Self::Discovery) => true,
            (Self::Plan, Self::Plan) => true,
            (Self::Execute, Self::Execute) => true,
            (Self::Verify, Self::Verify) => true,
            (Self::Gate, Self::Gate) => true,

            // Feedback loops and re-routing between stations
            (Self::Execute, Self::Plan) => true,   // Ambiguity refinement back to planning
            (Self::Verify, Self::Execute) => true, // Anomaly detected during verification
            (Self::Verify, Self::Plan) => true,    // Ambiguity refinement back to planning
            (Self::Gate, Self::Verify) => true,    // Gate rejection requiring replay/juror check

            // Any active station can transition to Failed on fatal error or abort
            (Self::Recon, Self::Failed)
            | (Self::Discovery, Self::Failed)
            | (Self::Plan, Self::Failed)
            | (Self::Execute, Self::Failed)
            | (Self::Verify, Self::Failed)
            | (Self::Gate, Self::Failed) => true,
            _ => false,
        }
    }
}

/// Dynamic routing conditions driving StateGraph edge selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RoutingCondition {
    /// Standard sequential forward progression to the next station.
    NormalProgression,
    /// Real-time anomaly or vulnerability leak detected requiring re-execution wave or loop.
    AnomalyDetected,
    /// Ambiguity or missing domain context requiring prompt/plan/directive refinement.
    AmbiguityRefine,
    /// High-risk or inconsistent result requiring independent replay / taint juror verification.
    ReplayRequired,
    /// Terminal failure or unrecoverable fatal error.
    FatalError,
}

/// A record of an individual transition between pipeline states.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TransitionRecord {
    pub from: PipelineState,
    pub to: PipelineState,
    pub condition: Option<RoutingCondition>,
    pub timestamp: String,
    pub iteration: usize,
    pub reason: Option<String>,
}

/// Execution graph telemetry and transition metrics.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct GraphTelemetry {
    pub total_transitions: usize,
    pub iterations_per_station: BTreeMap<String, usize>,
    pub routing_events: Vec<TransitionRecord>,
    pub loop_bounds_exceeded_count: usize,
}

impl GraphTelemetry {
    pub fn record(
        &mut self,
        from: PipelineState,
        to: PipelineState,
        condition: Option<RoutingCondition>,
        timestamp: String,
        iteration: usize,
        reason: Option<String>,
    ) {
        self.total_transitions += 1;
        *self
            .iterations_per_station
            .entry(to.name().to_string())
            .or_insert(0) = iteration;
        self.routing_events.push(TransitionRecord {
            from,
            to,
            condition,
            timestamp,
            iteration,
            reason,
        });
    }
}

pub const DEFAULT_MAX_LOOP_ITERATIONS: usize = 10;

fn default_max_loop_iterations() -> usize {
    DEFAULT_MAX_LOOP_ITERATIONS
}

/// A node in the pipeline StateGraph tracking active station, history, telemetry, and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StationNode {
    current: PipelineState,
    history: Vec<PipelineState>,
    transitions: Vec<(PipelineState, PipelineState, String)>,
    metadata: BTreeMap<String, String>,
    #[serde(default = "default_max_loop_iterations")]
    max_loop_iterations: usize,
    #[serde(default)]
    telemetry: GraphTelemetry,
}

impl StationNode {
    /// Initialize StateGraph at a starting state (typically `PipelineState::Recon`).
    pub fn new(initial: PipelineState) -> Self {
        let mut telemetry = GraphTelemetry::default();
        telemetry
            .iterations_per_station
            .insert(initial.name().to_string(), 1);
        Self {
            current: initial,
            history: vec![initial],
            transitions: vec![],
            metadata: BTreeMap::new(),
            max_loop_iterations: DEFAULT_MAX_LOOP_ITERATIONS,
            telemetry,
        }
    }

    /// Set custom loop bounds limit.
    pub fn with_max_loop_iterations(mut self, limit: usize) -> Self {
        self.max_loop_iterations = limit;
        self
    }

    /// Set custom loop bounds limit dynamically.
    pub fn set_max_loop_iterations(&mut self, limit: usize) {
        self.max_loop_iterations = limit;
    }

    /// Return the maximum allowed loop iterations for any station.
    pub fn max_loop_iterations(&self) -> usize {
        self.max_loop_iterations
    }

    /// Return the currently active pipeline state.
    pub fn current_state(&self) -> PipelineState {
        self.current
    }

    /// Return the sequence of visited states.
    pub fn history(&self) -> &[PipelineState] {
        &self.history
    }

    /// Return historical legacy transitions tuple slice.
    pub fn transitions(&self) -> &[(PipelineState, PipelineState, String)] {
        &self.transitions
    }

    /// Return execution graph telemetry and transition recording.
    pub fn telemetry(&self) -> &GraphTelemetry {
        &self.telemetry
    }

    /// Number of times the given state has been entered (including initial state).
    pub fn loop_iteration_count(&self, state: PipelineState) -> usize {
        self.history.iter().filter(|&&s| s == state).count()
    }

    /// Compute target state for the current station given a routing condition.
    pub fn target_state_for(&self, condition: &RoutingCondition) -> Option<PipelineState> {
        match (self.current, condition) {
            // FatalError from any active state routes to Failed
            (PipelineState::Completed, _) | (PipelineState::Failed, _) => None,
            (_, RoutingCondition::FatalError) => Some(PipelineState::Failed),

            // Recon:
            (PipelineState::Recon, RoutingCondition::NormalProgression) => {
                Some(PipelineState::Discovery)
            }
            (PipelineState::Recon, RoutingCondition::AmbiguityRefine) => {
                Some(PipelineState::Recon)
            }

            // Discovery:
            (PipelineState::Discovery, RoutingCondition::NormalProgression) => {
                Some(PipelineState::Plan)
            }
            (PipelineState::Discovery, RoutingCondition::AmbiguityRefine) => {
                Some(PipelineState::Discovery)
            }

            // Plan:
            (PipelineState::Plan, RoutingCondition::NormalProgression) => {
                Some(PipelineState::Execute)
            }
            (PipelineState::Plan, RoutingCondition::AmbiguityRefine) => Some(PipelineState::Plan),

            // Execute:
            (PipelineState::Execute, RoutingCondition::NormalProgression) => {
                Some(PipelineState::Verify)
            }
            (PipelineState::Execute, RoutingCondition::AnomalyDetected) => {
                Some(PipelineState::Execute)
            }
            (PipelineState::Execute, RoutingCondition::AmbiguityRefine) => {
                Some(PipelineState::Plan)
            }

            // Verify:
            (PipelineState::Verify, RoutingCondition::NormalProgression) => {
                Some(PipelineState::Gate)
            }
            (PipelineState::Verify, RoutingCondition::ReplayRequired) => {
                Some(PipelineState::Verify)
            }
            (PipelineState::Verify, RoutingCondition::AnomalyDetected) => {
                Some(PipelineState::Execute)
            }
            (PipelineState::Verify, RoutingCondition::AmbiguityRefine) => {
                Some(PipelineState::Plan)
            }

            // Gate:
            (PipelineState::Gate, RoutingCondition::NormalProgression) => {
                Some(PipelineState::Completed)
            }
            (PipelineState::Gate, RoutingCondition::AmbiguityRefine) => {
                Some(PipelineState::Verify)
            }
            (PipelineState::Gate, RoutingCondition::ReplayRequired) => {
                Some(PipelineState::Verify)
            }

            _ => None,
        }
    }

    /// Check if the station can conditionally route with `condition`.
    pub fn can_route(&self, condition: &RoutingCondition) -> bool {
        if let Some(target) = self.target_state_for(condition) {
            self.current.can_transition_to(target)
        } else {
            false
        }
    }

    /// Route to the next state based on the provided condition, checking loop bounds.
    pub fn route(&mut self, condition: RoutingCondition) -> Result<PipelineState> {
        let target = self.target_state_for(&condition).ok_or_else(|| {
            anyhow::anyhow!(
                "no valid routing edge from state {:?} with condition {:?}",
                self.current,
                condition
            )
        })?;

        self.transition_internal(target, Some(condition), None)?;
        Ok(target)
    }

    /// Validate and execute transition to `next`.
    pub fn transition_to(&mut self, next: PipelineState) -> Result<()> {
        self.transition_internal(next, None, None)
    }

    /// Validate and execute transition to `next` with a descriptive reason.
    pub fn transition_with_reason(&mut self, next: PipelineState, reason: &str) -> Result<()> {
        self.transition_internal(next, None, Some(reason.to_string()))
    }

    fn transition_internal(
        &mut self,
        next: PipelineState,
        condition: Option<RoutingCondition>,
        reason: Option<String>,
    ) -> Result<()> {
        if !self.current.can_transition_to(next) {
            bail!(
                "invalid pipeline station transition from {:?} to {:?}",
                self.current,
                next
            );
        }

        let next_count = self.loop_iteration_count(next) + 1;
        if next_count > self.max_loop_iterations {
            self.telemetry.loop_bounds_exceeded_count += 1;
            bail!(
                "loop bound exceeded for station {:?}: maximum {} iterations reached",
                next,
                self.max_loop_iterations
            );
        }

        let from = self.current;
        let ts = crate::agent::store::now_iso();
        self.current = next;
        self.history.push(next);
        self.transitions.push((from, next, ts.clone()));
        self.telemetry
            .record(from, next, condition, ts, next_count, reason);
        Ok(())
    }

    /// Record station execution metadata.
    pub fn set_metadata(&mut self, key: &str, value: &str) {
        self.metadata.insert(key.to_string(), value.to_string());
    }

    /// Retrieve station execution metadata.
    pub fn get_metadata(&self, key: &str) -> Option<&str> {
        self.metadata.get(key).map(|s| s.as_str())
    }
}
