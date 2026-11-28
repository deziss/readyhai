use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use tree_sitter::Parser;

use crate::model::{Finding, Severity};

pub const MAX_FILES: usize = 2500;
pub const MAX_FILE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    Python,
    JavaScript,
    TypeScript,
    Tsx,
    Go,
    Php,
}

impl Lang {
    pub fn from_path(path: &Path) -> Option<Self> {
        let ext = path.extension()?.to_str()?.to_ascii_lowercase();
        match ext.as_str() {
            "py" => Some(Self::Python),
            "js" | "mjs" | "cjs" | "jsx" => Some(Self::JavaScript),
            "ts" => Some(Self::TypeScript),
            "tsx" => Some(Self::Tsx),
            "go" => Some(Self::Go),
            "php" => Some(Self::Php),
            _ => None,
        }
    }

    /// Is this language's grammar compiled into this binary (see the `grammar-*` features)?
    pub fn grammar_available(self) -> bool {
        match self {
            Self::Python => cfg!(feature = "grammar-python"),
            Self::JavaScript => cfg!(feature = "grammar-javascript"),
            Self::TypeScript | Self::Tsx => cfg!(feature = "grammar-typescript"),
            Self::Go => cfg!(feature = "grammar-go"),
            Self::Php => cfg!(feature = "grammar-php"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Python => "python",
            Self::JavaScript => "javascript",
            Self::TypeScript => "typescript",
            Self::Tsx => "tsx",
            Self::Go => "go",
            Self::Php => "php",
        }
    }

    pub fn parser(self) -> Option<Parser> {
        // A missing grammar is None, never a silent wrong answer: the auditor counts those
        // files as skipped and the check reports them as Partial.
        let lang: Option<tree_sitter::Language> = match self {
            Self::Python => {
                #[cfg(feature = "grammar-python")]
                {
                    Some(tree_sitter_python::LANGUAGE.into())
                }
                #[cfg(not(feature = "grammar-python"))]
                {
                    None
                }
            }
            Self::JavaScript => {
                #[cfg(feature = "grammar-javascript")]
                {
                    Some(tree_sitter_javascript::LANGUAGE.into())
                }
                #[cfg(not(feature = "grammar-javascript"))]
                {
                    None
                }
            }
            Self::TypeScript => {
                #[cfg(feature = "grammar-typescript")]
                {
                    Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
                }
                #[cfg(not(feature = "grammar-typescript"))]
                {
                    None
                }
            }
            Self::Tsx => {
                #[cfg(feature = "grammar-typescript")]
                {
                    Some(tree_sitter_typescript::LANGUAGE_TSX.into())
                }
                #[cfg(not(feature = "grammar-typescript"))]
                {
                    None
                }
            }
            Self::Go => {
                #[cfg(feature = "grammar-go")]
                {
                    Some(tree_sitter_go::LANGUAGE.into())
                }
                #[cfg(not(feature = "grammar-go"))]
                {
                    None
                }
            }
            Self::Php => {
                #[cfg(feature = "grammar-php")]
                {
                    Some(tree_sitter_php::LANGUAGE_PHP.into())
                }
                #[cfg(not(feature = "grammar-php"))]
                {
                    None
                }
            }
        };
        let mut p = Parser::new();
        p.set_language(&lang?).ok()?;
        Some(p)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SinkKind {
    SqlInjection,
    CommandExec,
    Ssrf,
    PathTraversal,
    ServerSideTemplate,
}

impl SinkKind {
    pub fn rule_id(self) -> &'static str {
        match self {
            SinkKind::SqlInjection => "security.taint.sql_injection",
            SinkKind::CommandExec => "security.taint.command_exec",
            SinkKind::Ssrf => "security.taint.ssrf",
            SinkKind::PathTraversal => "security.taint.path_traversal",
            SinkKind::ServerSideTemplate => "security.taint.ssti",
        }
    }

    pub fn severity(self) -> Severity {
        match self {
            SinkKind::CommandExec => Severity::Critical,
            SinkKind::SqlInjection
            | SinkKind::Ssrf
            | SinkKind::PathTraversal
            | SinkKind::ServerSideTemplate => Severity::High,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            SinkKind::SqlInjection => "dynamic SQL execution",
            SinkKind::CommandExec => "dynamic OS command execution",
            SinkKind::Ssrf => "server-side HTTP request to dynamic URL",
            SinkKind::PathTraversal => "filesystem access with dynamic path",
            SinkKind::ServerSideTemplate => "template rendering with dynamic input",
        }
    }

    pub fn technique_hint(self) -> &'static str {
        match self {
            SinkKind::SqlInjection => "sqli",
            SinkKind::CommandExec => "cmdi",
            SinkKind::Ssrf => "ssrf",
            SinkKind::PathTraversal => "traversal",
            SinkKind::ServerSideTemplate => "ssti",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SinkHit {
    pub kind: SinkKind,
    pub file: String,
    pub line: u32,
    pub callee: String,
    pub via_fn: String,
}

#[derive(Debug, Clone)]
pub struct DiscoveredEndpoint {
    pub method: String,
    pub path: String,
    pub handler: String,
    pub file: String,
    pub line: u32,
    pub guards: Vec<String>,
    pub params: Vec<String>,
    pub sinks: Vec<SinkHit>,
}

#[derive(Debug, Default, Clone)]
pub struct CodeInventory {
    pub endpoints: Vec<DiscoveredEndpoint>,
    pub imports_by_file: BTreeMap<String, Vec<String>>,
    pub imported_packages: BTreeSet<String>,
    pub findings: Vec<Finding>,
    pub unreadable: Vec<String>,
    /// Files whose language grammar was compiled out (`grammar-*` features), reported so a
    /// narrowed build never claims an audit it did not perform. Format: `<lang>:<rel path>`.
    pub grammar_skipped: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct FunctionInfo {
    pub file: String,
    pub name: String,
    #[allow(dead_code)]
    pub line: u32,
    pub params: Vec<String>,
    pub calls: Vec<String>,
    pub sinks: Vec<SinkHit>,
}

#[derive(Debug, Clone)]
pub struct RawEndpoint {
    pub method: String,
    pub path: String,
    pub handler: String,
    pub file: String,
    pub line: u32,
    pub guards: Vec<String>,
    pub params: Vec<String>,
    pub inline_calls: Vec<String>,
    pub inline_sinks: Vec<SinkHit>,
}

pub fn remediation_for(k: SinkKind) -> &'static str {
    match k {
        SinkKind::SqlInjection => {
            "Use parameterized queries / prepared statements instead of formatting or concatenating SQL."
        }
        SinkKind::CommandExec => {
            "Avoid shell invocation; pass static command arrays directly without shell=True or sh -c."
        }
        SinkKind::Ssrf => {
            "Validate outbound URLs against an explicit host/scheme allowlist and block loopback/metadata IPs."
        }
        SinkKind::PathTraversal => {
            "Canonicalize and constrain resolved file paths under an allowed base directory."
        }
        SinkKind::ServerSideTemplate => {
            "Render static template files with auto-escaping instead of compiling user strings as templates."
        }
    }
}
