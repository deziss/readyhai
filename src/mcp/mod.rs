//! MCP (Model Context Protocol) Server implementation for ReadyHai.
//!
//! Provides a JSON-RPC 2.0 stdio transport offering tools for readiness scanning,
//! check enumeration, run finding queries, and autonomous multi-agent security testing.

pub mod agent_bridge;
pub mod protocol;
pub mod scanner;
pub mod tools;

#[cfg(test)]
mod tests;

#[allow(unused_imports)]
pub use agent_bridge::{
    DiscoverArgs, JobGuard, RunIdArgs, Runner, SwarmArgs, agent_cancel, agent_discover,
    agent_status_in, agents_brief, parse_args, run_id_arg, since_brief, start_swarm, swarm_request,
};
#[allow(unused_imports)]
pub use protocol::{
    JOBS, MAX_AGENT_JOBS, SUPPORTED, State, UNTRUSTED, handle, isolate_stdio, jobs, serve_stdio,
    untrusted,
};
#[allow(unused_imports)]
pub use scanner::{
    mcp_allowed_roots, mcp_opts, precheck, summarize, tool_findings, tool_scan, trunc, under_roots,
};
#[allow(unused_imports)]
pub use tools::{call_agent_tool, call_tool, tool_defs};
