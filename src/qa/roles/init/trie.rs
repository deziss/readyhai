use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V {
    Allow,
    Deny,
    /// Methods of one path disagree: globs match paths, so none is written.
    Mixed,
}

pub fn join(a: Option<V>, b: V) -> V {
    match a {
        None => b,
        Some(x) if x == b => b,
        _ => V::Mixed,
    }
}

/// Path as glob segments: `{id}` and any other glob metacharacter become wildcards.
pub fn segments(path: &str) -> Vec<String> {
    path.split('/')
        .filter(|s| !s.is_empty())
        .map(|seg| {
            let mut out = String::new();
            let mut depth = 0;
            for c in seg.chars() {
                match c {
                    '{' => {
                        if depth == 0 {
                            out.push('*');
                        }
                        depth += 1;
                    }
                    '}' if depth > 0 => depth -= 1,
                    _ if depth > 0 => {}
                    '*' | '?' | '[' | ']' | '}' | '\\' => out.push('?'),
                    c => out.push(c),
                }
            }
            out
        })
        .collect()
}

#[derive(Default)]
pub struct Node {
    pub kids: BTreeMap<String, Node>,
    /// Verdict of the operations that end exactly here.
    pub here: Option<V>,
    /// Verdict of everything at or below this node (None = no operation).
    pub agg: Option<V>,
}

impl Node {
    pub fn insert(&mut self, segs: &[String], v: V) {
        match segs.split_first() {
            None => self.here = Some(join(self.here, v)),
            Some((s, rest)) => self.kids.entry(s.clone()).or_default().insert(rest, v),
        }
    }

    pub fn finish(&mut self) {
        let mut agg = self.here;
        for k in self.kids.values_mut() {
            k.finish();
            if let Some(v) = k.agg {
                agg = Some(join(agg, v));
            }
        }
        self.agg = agg;
    }

    /// Smallest glob lists that say the same: a subtree whose operations all agree becomes
    /// `<prefix>/**`; a subtree that disagrees is split further.
    pub fn emit(
        &self,
        prefix: &str,
        allow: &mut Vec<String>,
        deny: &mut Vec<String>,
        mixed: &mut dyn FnMut(&str),
    ) {
        let exact = if prefix.is_empty() { "/" } else { prefix };
        let mut put = |v: V, pat: String| match v {
            V::Allow => allow.push(pat),
            V::Deny => deny.push(pat),
            V::Mixed => {}
        };
        match self.agg {
            None => {}
            Some(v @ (V::Allow | V::Deny)) => {
                if self.kids.is_empty() {
                    put(v, exact.to_string());
                } else {
                    if self.here.is_some() {
                        put(v, exact.to_string());
                    }
                    put(v, format!("{prefix}/**"));
                }
            }
            Some(V::Mixed) => {
                match self.here {
                    Some(V::Mixed) => mixed(exact),
                    Some(v) => put(v, exact.to_string()),
                    None => {}
                }
                for (seg, k) in &self.kids {
                    k.emit(&format!("{prefix}/{seg}"), allow, deny, mixed);
                }
            }
        }
    }
}

pub fn concrete_path(path: &str) -> String {
    let mut out = String::new();
    let mut depth = 0;
    for c in path.chars() {
        match c {
            '{' => {
                if depth == 0 {
                    out.push('1');
                }
                depth += 1;
            }
            '}' if depth > 0 => depth -= 1,
            _ if depth > 0 => {}
            c => out.push(c),
        }
    }
    out
}
