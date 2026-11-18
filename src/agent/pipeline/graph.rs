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
            // Adaptive ReAct loop iteration within execution station
            (Self::Execute, Self::Execute) => true,
            (Self::Verify, Self::Gate) => true,
            (Self::Gate, Self::Completed) => true,
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

/// A node in the pipeline StateGraph tracking active station, history, and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StationNode {
    current: PipelineState,
    history: Vec<PipelineState>,
    transitions: Vec<(PipelineState, PipelineState, String)>,
    metadata: std::collections::BTreeMap<String, String>,
}

impl StationNode {
    /// Initialize StateGraph at a starting state (typically `PipelineState::Recon`).
    pub fn new(initial: PipelineState) -> Self {
        Self {
            current: initial,
            history: vec![initial],
            transitions: vec![],
            metadata: std::collections::BTreeMap::new(),
        }
    }

    /// Return the currently active pipeline state.
    pub fn current_state(&self) -> PipelineState {
        self.current
    }

    /// Return the sequence of visited states.
    pub fn history(&self) -> &[PipelineState] {
        &self.history
    }

    /// Validate and execute transition to `next`.
    pub fn transition_to(&mut self, next: PipelineState) -> Result<()> {
        if !self.current.can_transition_to(next) {
            bail!(
                "invalid pipeline station transition from {:?} to {:?}",
                self.current,
                next
            );
        }
        let from = self.current;
        self.current = next;
        self.history.push(next);
        self.transitions.push((from, next, crate::agent::store::now_iso()));
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
