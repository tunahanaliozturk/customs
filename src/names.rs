//! Rules C401 to C403 over package IDs: characters outside ASCII, look-alikes
//! of a popular ID, and near misses of one. The popular IDs are embedded from
//! `data/popular-ids.txt` and `data/targeted-ids.txt` when customs is built;
//! the tool never fetches them.
//!
//! IDs are compared as skeletons: the ID lowercased as `NuGet` lowercases it,
//! mapped to its UTS #39 confusable skeleton, and lowercased again, so that a
//! lock file that writes an ID in another case, and a digit that looks like a
//! capital letter, compare as they display (ADR 0007).

use std::collections::{BTreeSet, HashMap};
use std::fmt::Write as _;
use std::sync::LazyLock;

use crate::graph::{PackageId, lower_invariant};
use crate::scan::{Finding, FindingRule};

const POPULAR: &str = include_str!("../data/popular-ids.txt");
const TARGETED: &str = include_str!("../data/targeted-ids.txt");

/// IDs shorter than this, in characters, get no C403: among short IDs one
/// edit is the distance between unrelated names.
const NEAR_MISS_MIN: usize = 6;

/// The characters that `NuGet` allows between the parts of an ID.
const SEPARATORS: [char; 3] = ['.', '-', '_'];

/// The skeleton of an ID, as this module compares IDs.
pub(crate) fn skeleton(id: &str) -> String {
    let lower = lower_invariant(id);
    lower_invariant(&unicode_security::skeleton(&lower).collect::<String>())
}

struct Popular {
    id: &'static str,
    lower: String,
    skeleton: Vec<char>,
}

struct Index {
    entries: Vec<Popular>,
    by_lower: HashMap<String, usize>,
    by_skeleton: HashMap<String, Vec<usize>>,
    /// Skeletons without separators.
    by_bare: HashMap<String, Vec<usize>>,
    /// Skeletons by their length in characters.
    by_length: HashMap<usize, Vec<usize>>,
}

/// The embedded IDs: one per line, comments with `#`, and in the targeted
/// list the ID before ` | `.
fn embedded() -> impl Iterator<Item = &'static str> {
    POPULAR
        .lines()
        .chain(TARGETED.lines())
        .map(|line| line.split(" | ").next().unwrap_or(line).trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
}

static INDEX: LazyLock<Index> = LazyLock::new(|| {
    let mut index = Index {
        entries: Vec::new(),
        by_lower: HashMap::new(),
        by_skeleton: HashMap::new(),
        by_bare: HashMap::new(),
        by_length: HashMap::new(),
    };
    for id in embedded() {
        let lower = lower_invariant(id);
        if index.by_lower.contains_key(&lower) {
            continue;
        }
        let at = index.entries.len();
        let skeleton = skeleton(id);
        index.by_lower.insert(lower.clone(), at);
        index.by_bare.entry(bare(&skeleton)).or_default().push(at);
        let chars: Vec<char> = skeleton.chars().collect();
        index.by_length.entry(chars.len()).or_default().push(at);
        index.by_skeleton.entry(skeleton).or_default().push(at);
        index.entries.push(Popular {
            id,
            lower,
            skeleton: chars,
        });
    }
    index
});

fn bare(skeleton: &str) -> String {
    skeleton
        .chars()
        .filter(|c| !SEPARATORS.contains(c))
        .collect()
}

/// Whether the optimal string alignment distance of two different strings
/// is exactly 1: one substitution, insertion, deletion, or swap of two
/// neighbours. Linear in their length.
fn one_edit(a: &[char], b: &[char]) -> bool {
    let (short, long) = if a.len() <= b.len() { (a, b) } else { (b, a) };
    let Some(first) = short.iter().zip(long).position(|(x, y)| x != y) else {
        // One is a prefix of the other.
        return long.len() == short.len() + 1;
    };
    match long.len() - short.len() {
        0 => {
            short.get(first + 1..) == long.get(first + 1..)
                || (short.get(first) == long.get(first + 1)
                    && short.get(first + 1) == long.get(first)
                    && short.get(first + 2..) == long.get(first + 2..))
        }
        1 => short.get(first..) == long.get(first + 1..),
        _ => false,
    }
}

/// How an ID resembles a popular one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Likeness {
    /// The same skeleton: C402.
    Skeleton,
    /// One edit between the skeletons: C403.
    OneEdit,
    /// The skeletons differ only in separators: C403.
    Separators,
}

/// Every popular ID other than `id` itself that `id` resembles, with how.
/// Popular IDs are not exempt here; [`check`] exempts them.
fn resemblances(id: &PackageId) -> BTreeSet<(Likeness, &'static str)> {
    let index = &*INDEX;
    let skeleton = skeleton(id.as_str());
    let other = |at: &usize| index.entries.get(*at).filter(|p| p.lower != id.lower());
    let mut found = BTreeSet::new();
    for popular in index
        .by_skeleton
        .get(&skeleton)
        .into_iter()
        .flatten()
        .filter_map(other)
    {
        found.insert((Likeness::Skeleton, popular.id));
    }
    if id.as_str().chars().count() < NEAR_MISS_MIN {
        return found;
    }
    let chars: Vec<char> = skeleton.chars().collect();
    let same_skeleton: BTreeSet<&str> = found.iter().map(|(_, p)| *p).collect();
    let near = chars.len().saturating_sub(1)..=chars.len() + 1;
    for popular in near
        .filter_map(|length| index.by_length.get(&length))
        .flatten()
        .filter_map(other)
    {
        if one_edit(&chars, &popular.skeleton) {
            found.insert((Likeness::OneEdit, popular.id));
        }
    }
    for popular in index
        .by_bare
        .get(&bare(&skeleton))
        .into_iter()
        .flatten()
        .filter_map(other)
    {
        if !same_skeleton.contains(popular.id) && !found.contains(&(Likeness::OneEdit, popular.id))
        {
            found.insert((Likeness::Separators, popular.id));
        }
    }
    found
}

/// Whether `id` is one of the embedded popular or targeted IDs.
pub(crate) fn is_popular(id: &PackageId) -> bool {
    INDEX.by_lower.contains_key(id.lower())
}

/// The findings of rules C401 to C403 for one package ID. A popular ID is
/// what look-alikes imitate, so it gets no C402 or C403 itself; which
/// popular IDs resemble each other is reviewed in `data/popular-pairs.txt`.
pub(crate) fn check(id: &PackageId) -> Vec<Finding> {
    let mut findings = Vec::new();
    let outside: Vec<char> = id.as_str().chars().filter(|c| !c.is_ascii()).collect();
    if !outside.is_empty() {
        let mut listed = String::new();
        for c in outside.iter().take(10) {
            let separator = if listed.is_empty() { "" } else { ", " };
            let _ = write!(listed, "{separator}U+{:04X}", u32::from(*c));
        }
        if outside.len() > 10 {
            let _ = write!(listed, " and {} more", outside.len() - 10);
        }
        findings.push(Finding::new(
            FindingRule::C401,
            None,
            format!("package ID with characters outside ASCII: {listed}"),
        ));
    }
    if is_popular(id) {
        return findings;
    }
    for (likeness, popular) in resemblances(id) {
        let (rule, message) = match likeness {
            Likeness::Skeleton => (
                FindingRule::C402,
                format!(
                    "looks like the popular package {popular}: the same skeleton under Unicode confusables"
                ),
            ),
            Likeness::OneEdit => (
                FindingRule::C403,
                format!("one edit from the popular package {popular}"),
            ),
            Likeness::Separators => (
                FindingRule::C403,
                format!("differs from the popular package {popular} only in separators"),
            ),
        };
        let mut finding = Finding::new(rule, None, message);
        finding.evidence = Some(popular.to_owned());
        findings.push(finding);
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(text: &str) -> PackageId {
        PackageId::new(text).unwrap()
    }

    fn rules(text: &str) -> Vec<(&'static str, Option<String>)> {
        check(&id(text))
            .into_iter()
            .map(|f| (f.rule.id(), f.evidence))
            .collect()
    }

    fn popular(text: &str) -> Option<String> {
        PackageId::new(text).ok().map(|id| id.as_str().to_owned())
    }

    #[test]
    fn the_embedded_lists_hold_the_popular_and_the_targeted_ids() {
        assert!(INDEX.entries.len() > 4_000, "{}", INDEX.entries.len());
        for text in [
            "Newtonsoft.Json",
            "Stripe.net",
            "Serilog",
            "Guna.UI2.WinForms",
        ] {
            assert!(is_popular(&id(text)), "{text}");
        }
        assert!(!is_popular(&id("StripeApi.Net")));
    }

    #[test]
    fn the_armenian_look_alike_of_guna_is_c401_and_c402() {
        // Armenian seh and vo in place of u and n.
        assert_eq!(
            rules("Gսոa.UI2.WinForms"),
            [("C401", None), ("C402", popular("Guna.UI2.WinForms"))]
        );
        // In the lowercase form a lock file may hold.
        assert_eq!(
            rules("gսոa.ui2.winforms"),
            [("C401", None), ("C402", popular("Guna.UI2.WinForms"))]
        );
    }

    #[test]
    fn the_published_campaign_id_is_c401_and_one_edit_from_guna() {
        // The ID of the 2024 campaign also changed UI2 to UI3, so its
        // skeleton is one edit away rather than equal.
        assert_eq!(
            rules("Gսոa.UI3.Wіnfօrms"),
            [("C401", None), ("C403", popular("Guna.UI2.WinForms"))]
        );
    }

    #[test]
    fn a_one_edit_and_a_separator_only_variant_are_c403() {
        assert_eq!(
            rules("Newtonsoft.Jsn"),
            [("C403", popular("Newtonsoft.Json"))]
        );
        assert_eq!(
            rules("Newtonsoft.Josn"),
            [("C403", popular("Newtonsoft.Json"))]
        );
        assert_eq!(
            rules("Newtonsoft.Jsoon"),
            [("C403", popular("Newtonsoft.Json"))]
        );
        assert_eq!(
            rules("Microsoft_Extensions-Logging"),
            [("C403", popular("Microsoft.Extensions.Logging"))]
        );
    }

    #[test]
    fn a_digit_in_place_of_a_letter_is_a_look_alike() {
        assert_eq!(rules("Seri1og"), [("C402", popular("Serilog"))]);
        assert_eq!(
            rules("Newtonsoft.Js0n"),
            [("C402", popular("Newtonsoft.Json"))]
        );
    }

    #[test]
    fn an_id_that_extends_a_popular_one_is_not_flagged() {
        // The 2026 StripeApi.Net case: a known gap, kept visible.
        assert_eq!(rules("StripeApi.Net"), []);
        assert_eq!(rules("ZendeskApi.Client.V2"), []);
    }

    #[test]
    fn popular_ids_and_short_ids_get_no_near_miss() {
        assert_eq!(rules("Newtonsoft.Json"), []);
        assert_eq!(rules("NEWTONSOFT.JSON"), []);
        assert_eq!(rules("Guna.UI2.WinForms"), []);
        // NUnit.Engine and TUnit.Engine are one edit apart and both popular:
        // a reviewed pair, so neither is reported.
        assert_eq!(rules("NUnit.Engine"), []);
        assert_eq!(rules("TUnit.Engine"), []);
        // Moq is popular; Moqq is one edit from it but too short.
        assert_eq!(rules("Moqq"), []);
    }

    #[test]
    fn one_edit_is_exactly_one_edit() {
        let chars = |s: &str| s.chars().collect::<Vec<_>>();
        let yes = [
            ("abc", "abd"),
            ("abc", "ab"),
            ("abc", "abcd"),
            ("abc", "bac"),
            ("abc", "xabc"),
            ("ab", "ba"),
        ];
        for (a, b) in yes {
            assert!(one_edit(&chars(a), &chars(b)), "{a} {b}");
            assert!(one_edit(&chars(b), &chars(a)), "{b} {a}");
        }
        let no = [
            ("abc", "abc"),
            ("abc", "a"),
            ("abcd", "badc"),
            ("abc", "cba"),
            ("abc", "xyz"),
            ("", ""),
        ];
        for (a, b) in no {
            assert!(!one_edit(&chars(a), &chars(b)), "{a} {b}");
        }
    }

    /// The self-test of the list: which popular IDs resemble another popular
    /// ID must be exactly the pairs reviewed in `data/popular-pairs.txt`.
    #[test]
    fn no_popular_id_resembles_another_outside_the_reviewed_pairs() {
        let reviewed: BTreeSet<(String, String)> = include_str!("../data/popular-pairs.txt")
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| {
                let mut fields = l.split(" | ");
                let a = fields.next().unwrap().trim().to_lowercase();
                let b = fields.next().unwrap().trim().to_lowercase();
                assert!(
                    fields.next().is_some_and(|r| !r.trim().is_empty()),
                    "no reason: {l}"
                );
                (a.clone().min(b.clone()), a.max(b))
            })
            .collect();
        let mut found = BTreeSet::new();
        for popular in &INDEX.entries {
            for (_, other) in resemblances(&id(popular.id)) {
                let (a, b) = (popular.id.to_lowercase(), other.to_lowercase());
                found.insert((a.clone().min(b.clone()), a.max(b)));
            }
        }
        let unlisted: Vec<_> = found.difference(&reviewed).collect();
        let stale: Vec<_> = reviewed.difference(&found).collect();
        assert!(
            unlisted.is_empty() && stale.is_empty(),
            "{} unreviewed pairs:\n{}\n{} listed pairs no longer found: {stale:?}",
            unlisted.len(),
            unlisted
                .iter()
                .map(|(a, b)| format!("{a} | {b} | "))
                .collect::<Vec<_>>()
                .join("\n"),
            stale.len()
        );
    }
}
