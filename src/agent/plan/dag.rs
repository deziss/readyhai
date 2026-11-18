//! Directed Acyclic Graph (DAG) for stateful multi-step attack workflows.
//!
//! Models sequential and branch-dependent adversarial testing steps,
//! enforces cycle detection, and computes topological execution orders.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

use crate::agent::types::{PlannedCase, StatefulStep};

/// A single step/node in the attack DAG.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttackDagNode {
    /// Unique identifier for this attack step (e.g., "setup_user", "escalate_role").
    pub id: String,
    /// List of node IDs that must successfully execute before this node can run.
    pub dependencies: Vec<String>,
    /// High-level action or goal description.
    #[serde(default)]
    pub action: Option<String>,
    /// Target URI or path component (e.g., "/api/auth/login", "/api/v1/tenant").
    #[serde(default)]
    pub component: Option<String>,
    /// HTTP method (GET, POST, PUT, DELETE, etc.).
    #[serde(default)]
    pub method: Option<String>,
    /// Optional JSON payload for the request.
    #[serde(default)]
    pub payload: Option<serde_json::Value>,
    /// Expected HTTP status code if known.
    #[serde(default)]
    pub expected_status: Option<u16>,
    /// Embedded planned case if pre-synthesized.
    #[serde(default)]
    pub planned_case: Option<PlannedCase>,
}

impl AttackDagNode {
    /// Create a new attack DAG node with an ID and dependency IDs.
    pub fn new(id: impl Into<String>, dependencies: Vec<String>) -> Self {
        Self {
            id: id.into(),
            dependencies,
            action: None,
            component: None,
            method: None,
            payload: None,
            expected_status: None,
            planned_case: None,
        }
    }

    /// Set the action description.
    pub fn with_action(mut self, action: impl Into<String>) -> Self {
        self.action = Some(action.into());
        self
    }

    /// Set the target path/component.
    pub fn with_component(mut self, component: impl Into<String>) -> Self {
        self.component = Some(component.into());
        self
    }

    /// Set the HTTP method.
    pub fn with_method(mut self, method: impl Into<String>) -> Self {
        self.method = Some(method.into());
        self
    }

    /// Set the payload.
    pub fn with_payload(mut self, payload: serde_json::Value) -> Self {
        self.payload = Some(payload);
        self
    }

    /// Set the expected HTTP status.
    pub fn with_expected_status(mut self, status: u16) -> Self {
        self.expected_status = Some(status);
        self
    }

    /// Attach a full planned case.
    pub fn with_case(mut self, case: PlannedCase) -> Self {
        self.planned_case = Some(case);
        self
    }
}

/// Attack Directed Acyclic Graph (DAG) for managing interdependent testing workflows.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AttackDag {
    /// Ordered list of nodes registered in the DAG.
    pub nodes: Vec<AttackDagNode>,
}

impl AttackDag {
    /// Create an empty attack DAG.
    pub fn new() -> Self {
        Self { nodes: Vec::new() }
    }

    /// Add or update a node in the DAG.
    pub fn add_node(&mut self, node: AttackDagNode) {
        if let Some(existing) = self.nodes.iter_mut().find(|n| n.id == node.id) {
            *existing = node;
        } else {
            self.nodes.push(node);
        }
    }

    /// Get a node by ID.
    pub fn get_node(&self, id: &str) -> Option<&AttackDagNode> {
        self.nodes.iter().find(|n| n.id == id)
    }

    /// Get a mutable reference to a node by ID.
    pub fn get_node_mut(&mut self, id: &str) -> Option<&mut AttackDagNode> {
        self.nodes.iter_mut().find(|n| n.id == id)
    }

    /// Get the dependencies of a specific node.
    pub fn dependencies_of(&self, node_id: &str) -> Vec<String> {
        self.get_node(node_id)
            .map(|n| n.dependencies.clone())
            .unwrap_or_default()
    }

    /// Get all nodes that depend directly on the given node.
    pub fn dependents_of(&self, node_id: &str) -> Vec<String> {
        self.nodes
            .iter()
            .filter(|n| n.dependencies.iter().any(|d| d == node_id))
            .map(|n| n.id.clone())
            .collect()
    }

    /// Check if the DAG contains any cycles or missing dependencies.
    pub fn detect_cycle(&self) -> bool {
        self.topological_order().is_err()
    }

    /// Check if the DAG is cyclic.
    pub fn is_cyclic(&self) -> bool {
        self.detect_cycle()
    }

    /// Compute a topological execution order of node IDs.
    /// Returns `Err` if a cycle, self-loop, or missing dependency is detected.
    pub fn topological_order(&self) -> Result<Vec<String>, String> {
        let mut in_degree: HashMap<&str, usize> = HashMap::new();
        let mut dependents: HashMap<&str, Vec<&str>> = HashMap::new();
        let all_ids: HashSet<&str> = self.nodes.iter().map(|n| n.id.as_str()).collect();

        for node in &self.nodes {
            in_degree.entry(node.id.as_str()).or_insert(0);
            for dep in &node.dependencies {
                if dep == &node.id {
                    return Err(format!("self-dependency cycle detected on node '{}'", node.id));
                }
                if !all_ids.contains(dep.as_str()) {
                    return Err(format!("missing dependency '{}' for node '{}'", dep, node.id));
                }
                *in_degree.entry(node.id.as_str()).or_insert(0) += 1;
                dependents.entry(dep.as_str()).or_default().push(node.id.as_str());
            }
        }

        // Initialize queue with in-degree 0 nodes in insertion order for determinism
        let mut queue: VecDeque<&str> = VecDeque::new();
        for node in &self.nodes {
            if in_degree.get(node.id.as_str()) == Some(&0) {
                queue.push_back(node.id.as_str());
            }
        }

        let mut order: Vec<String> = Vec::with_capacity(self.nodes.len());
        while let Some(curr) = queue.pop_front() {
            order.push(curr.to_string());
            if let Some(deps) = dependents.get(curr) {
                for &next in deps {
                    if let Some(deg) = in_degree.get_mut(next) {
                        *deg -= 1;
                        if *deg == 0 {
                            queue.push_back(next);
                        }
                    }
                }
            }
        }

        if order.len() != self.nodes.len() {
            Err("cycle detected in attack DAG".into())
        } else {
            Ok(order)
        }
    }

    /// Convert topologically sorted nodes into a sequence of StatefulSteps for multi-stage workflow execution.
    pub fn to_stateful_steps(&self) -> Result<Vec<StatefulStep>, String> {
        let order = self.topological_order()?;
        let mut steps = Vec::new();
        for (idx, node_id) in order.iter().enumerate() {
            if let Some(node) = self.get_node(node_id) {
                let method = node.method.clone().unwrap_or_else(|| "GET".into());
                let path = node.component.clone().unwrap_or_else(|| format!("/{node_id}"));
                let payload = node.payload.as_ref().map(|p| p.to_string());
                steps.push(StatefulStep {
                    step_number: (idx + 1) as u32,
                    actor: "user".into(),
                    method,
                    path,
                    payload,
                    extract_vars: Some(vec!["id".into(), "token".into(), "tenant_id".into()]),
                    expected_status: node.expected_status,
                    violation_condition: Some(
                        "Server returned unauthorized data or elevated privileges".into(),
                    ),
                });
            }
        }
        Ok(steps)
    }

    /// Convert the DAG into a planned case with stateful multi-step workflow (borrowed).
    pub fn to_planned_case(&self, title: &str, component: &str) -> Result<PlannedCase, String> {
        let steps = self.to_stateful_steps()?;
        let c = PlannedCase {
            id: String::new(),
            title: title.to_string(),
            component: component.to_string(),
            method: "POST".into(),
            technique: "state_transition".into(),
            input_hint: format!("Attack DAG stateful workflow with {} steps", steps.len()),
            payload: None,
            headers: Vec::new(),
            content_type: Some("application/json".into()),
            probe_oracle: None,
            expected_behavior:
                "Stateful attack workflow must be bounded and enforced by authorization guards"
                    .into(),
            expected_status: Some(403),
            risk_level: "high".into(),
            role: Some("user".into()),
            secured: Some(true),
            route_status: None,
            expect_fields: Vec::new(),
            expected_content_type: None,
            source: Some("attack_dag".into()),
            stateful_steps: Some(steps),
            concurrency_burst: None,
            contract: None,
            changed_ops: Vec::new(),
            area: "stateful".into(),
            regression_of: Vec::new(),
            history_priority: false,
        };
        Ok(c)
    }

    /// Convert the DAG into a planned case with stateful multi-step workflow (consumed).
    pub fn into_planned_case(self, title: &str, component: &str) -> Result<PlannedCase, String> {
        self.to_planned_case(title, component)
    }
}
