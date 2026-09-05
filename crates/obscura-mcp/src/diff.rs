use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Recorded snapshot/markdown baseline state for a tab.
#[derive(Debug, Clone)]
pub struct DiffBaseline {
    pub url: String,
    pub mode: String,
    pub lines: Vec<String>,
    pub taken_at: std::time::Instant,
}

/// Normalize lines by trimming trailing whitespace and dropping lines matching any regex in `ignore`.
pub fn normalize(lines: Vec<String>, ignore: &[regex::Regex]) -> Vec<String> {
    lines
        .into_iter()
        .map(|line| line.trim_end().to_string())
        .filter(|line| !ignore.iter().any(|re| re.is_match(line)))
        .collect()
}

fn hash_line(s: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    s.hash(&mut hasher);
    hasher.finish()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiffOp {
    Keep(usize, usize), // (old_idx, new_idx)
    Delete(usize),      // old_idx
    Insert(usize),      // new_idx
}

/// Pure-Rust, zero-external-dependency line-level LCS unified diff algorithm.
///
/// Returns `(diff_text, added_count, removed_count, truncated)`.
pub fn unified_diff(
    old: &[String],
    new: &[String],
    ctx: usize,
    max_lines: usize,
) -> (String, usize, usize, bool) {
    let n = old.len();
    let m = new.len();

    let old_hashes: Vec<u64> = old.iter().map(|s| hash_line(s)).collect();
    let new_hashes: Vec<u64> = new.iter().map(|s| hash_line(s)).collect();

    // Fast check for identical contents
    if n == m && old_hashes == new_hashes && old == new {
        return (String::new(), 0, 0, false);
    }

    // Standard LCS DP matrix on line hashes (with string equality check on collisions)
    let stride = m + 1;
    let mut dp = vec![0u32; (n + 1) * (m + 1)];

    for i in 0..n {
        for j in 0..m {
            if old_hashes[i] == new_hashes[j] && old[i] == new[j] {
                dp[(i + 1) * stride + (j + 1)] = dp[i * stride + j] + 1;
            } else {
                let up = dp[i * stride + (j + 1)];
                let left = dp[(i + 1) * stride + j];
                dp[(i + 1) * stride + (j + 1)] = up.max(left);
            }
        }
    }

    // Backtrack to build the sequence of operations
    let mut i = n;
    let mut j = m;
    let mut rev_ops = Vec::with_capacity(n + m);

    while i > 0 && j > 0 {
        if old_hashes[i - 1] == new_hashes[j - 1] && old[i - 1] == new[j - 1] {
            rev_ops.push(DiffOp::Keep(i - 1, j - 1));
            i -= 1;
            j -= 1;
        } else if dp[i * stride + (j - 1)] >= dp[(i - 1) * stride + j] {
            // Favor Insert when walking backwards so Delete precedes Insert when reversed
            rev_ops.push(DiffOp::Insert(j - 1));
            j -= 1;
        } else {
            rev_ops.push(DiffOp::Delete(i - 1));
            i -= 1;
        }
    }
    while i > 0 {
        rev_ops.push(DiffOp::Delete(i - 1));
        i -= 1;
    }
    while j > 0 {
        rev_ops.push(DiffOp::Insert(j - 1));
        j -= 1;
    }

    rev_ops.reverse();
    let ops = rev_ops;

    let mut added_count = 0;
    let mut removed_count = 0;
    let mut change_indices = Vec::new();

    for (k, op) in ops.iter().enumerate() {
        match op {
            DiffOp::Insert(_) => {
                added_count += 1;
                change_indices.push(k);
            }
            DiffOp::Delete(_) => {
                removed_count += 1;
                change_indices.push(k);
            }
            DiffOp::Keep(_, _) => {}
        }
    }

    if change_indices.is_empty() {
        return (String::new(), 0, 0, false);
    }

    // Group changes into unified diff hunks with context windows
    let mut hunk_ranges: Vec<(usize, usize)> = Vec::new();
    let mut cur_start = change_indices[0].saturating_sub(ctx);
    let mut cur_end = (change_indices[0] + ctx).min(ops.len() - 1);

    for &idx in &change_indices[1..] {
        let next_start = idx.saturating_sub(ctx);
        let next_end = (idx + ctx).min(ops.len() - 1);

        if next_start <= cur_end + 1 {
            cur_end = next_end;
        } else {
            hunk_ranges.push((cur_start, cur_end));
            cur_start = next_start;
            cur_end = next_end;
        }
    }
    hunk_ranges.push((cur_start, cur_end));

    // Prefix line counts in old and new before each op index
    let mut old_count_before = vec![0usize; ops.len() + 1];
    let mut new_count_before = vec![0usize; ops.len() + 1];
    for (k, op) in ops.iter().enumerate() {
        old_count_before[k + 1] = old_count_before[k]
            + match op {
                DiffOp::Keep(_, _) | DiffOp::Delete(_) => 1,
                DiffOp::Insert(_) => 0,
            };
        new_count_before[k + 1] = new_count_before[k]
            + match op {
                DiffOp::Keep(_, _) | DiffOp::Insert(_) => 1,
                DiffOp::Delete(_) => 0,
            };
    }

    let mut output_lines: Vec<String> = Vec::new();
    let mut truncated = false;

    'outer: for (h_start, h_end) in hunk_ranges {
        let old_len = old_count_before[h_end + 1] - old_count_before[h_start];
        let new_len = new_count_before[h_end + 1] - new_count_before[h_start];

        let old_start = if old_len > 0 {
            old_count_before[h_start] + 1
        } else {
            old_count_before[h_start]
        };

        let new_start = if new_len > 0 {
            new_count_before[h_start] + 1
        } else {
            new_count_before[h_start]
        };

        let header = format!("@@ -{old_start},{old_len} +{new_start},{new_len} @@");
        if output_lines.len() >= max_lines {
            truncated = true;
            break 'outer;
        }
        output_lines.push(header);

        for op in &ops[h_start..=h_end] {
            if output_lines.len() >= max_lines {
                truncated = true;
                break 'outer;
            }
            match op {
                DiffOp::Keep(o, _) => output_lines.push(format!(" {}", old[*o])),
                DiffOp::Delete(o) => output_lines.push(format!("-{}", old[*o])),
                DiffOp::Insert(n) => output_lines.push(format!("+{}", new[*n])),
            }
        }
    }

    (
        output_lines.join("\n"),
        added_count,
        removed_count,
        truncated,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_documents_produce_empty_diff() {
        let doc = vec!["alpha".to_string(), "beta".to_string(), "gamma".to_string()];
        let (diff_text, added, removed, truncated) = unified_diff(&doc, &doc, 2, 200);
        assert_eq!(diff_text, "");
        assert_eq!(added, 0);
        assert_eq!(removed, 0);
        assert!(!truncated);
    }

    #[test]
    fn inserted_lines_produce_single_hunk_with_added_count() {
        let old = vec!["one".to_string(), "two".to_string(), "five".to_string()];
        let new = vec![
            "one".to_string(),
            "two".to_string(),
            "three".to_string(),
            "four".to_string(),
            "five".to_string(),
        ];
        let (diff_text, added, removed, truncated) = unified_diff(&old, &new, 1, 200);
        assert_eq!(added, 2);
        assert_eq!(removed, 0);
        assert!(!truncated);
        assert!(diff_text.contains("@@ -2,2 +2,4 @@"));
        assert!(diff_text.contains("+three"));
        assert!(diff_text.contains("+four"));
        assert!(diff_text.contains(" two"));
        assert!(diff_text.contains(" five"));
    }

    #[test]
    fn deleted_lines_produce_hunk_with_removed_count() {
        let old = vec![
            "header".to_string(),
            "remove_a".to_string(),
            "remove_b".to_string(),
            "footer".to_string(),
        ];
        let new = vec!["header".to_string(), "footer".to_string()];
        let (diff_text, added, removed, truncated) = unified_diff(&old, &new, 1, 200);
        assert_eq!(added, 0);
        assert_eq!(removed, 2);
        assert!(!truncated);
        assert!(diff_text.contains("@@ -1,4 +1,2 @@"));
        assert!(diff_text.contains("-remove_a"));
        assert!(diff_text.contains("-remove_b"));
    }

    #[test]
    fn ignore_regex_successfully_suppresses_churn_lines() {
        let lines = vec![
            "Dashboard".to_string(),
            "Last updated: 14:23:45".to_string(),
            "Active users: 42".to_string(),
        ];
        let ignore = vec![regex::Regex::new(r"\d{2}:\d{2}:\d{2}").unwrap()];
        let normalized = normalize(lines, &ignore);
        assert_eq!(
            normalized,
            vec!["Dashboard".to_string(), "Active users: 42".to_string()]
        );
    }

    #[test]
    fn max_lines_truncation_flags_truncated() {
        let old = vec!["line 0".to_string()];
        let new: Vec<String> = (0..20).map(|i| format!("line {i}")).collect();
        let (diff_text, added, removed, truncated) = unified_diff(&old, &new, 2, 5);
        assert!(truncated);
        assert_eq!(added, 19);
        assert_eq!(removed, 0);
        assert_eq!(diff_text.lines().count(), 5);
    }
}
