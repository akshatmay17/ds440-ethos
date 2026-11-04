//! `ethos scanner-eval`: measures the **enforcing** `PromptInjectScanner`
//! (and, optionally, the advisory `SemanticGuard`) against a labelled JSONL
//! corpus, as precision / recall / F1.
//!
//! This is the scanner that actually fires in the agent loop and the daemon.
//! `scripts/eval_semantic_baseline.py` only measures a Python re-implementation
//! of SemanticGuard's keyword fallback; this runs the Rust code itself, so the
//! reported numbers match what the runtime enforces.
//!
//! Corpus: one JSON object per line, `{"text": str, "label": int}` with
//! `0 = BENIGN`, `1 = INJECTION`, `2 = JAILBREAK` (as produced by
//! `scripts/prepare_semantic_dataset.py`). Detection is binary: label 0 is
//! negative, 1 and 2 are positive.

use std::io::{BufRead, BufReader};

use crate::walls::promptinject::PromptInjectScanner;
use crate::walls::semantic::SemanticGuard;

#[derive(Default, Clone, Copy)]
struct Counts {
    tp: u64,
    fp: u64,
    tn: u64,
    fn_: u64,
}

impl Counts {
    fn observe(&mut self, predicted_positive: bool, actually_positive: bool) {
        match (predicted_positive, actually_positive) {
            (true, true) => self.tp += 1,
            (true, false) => self.fp += 1,
            (false, false) => self.tn += 1,
            (false, true) => self.fn_ += 1,
        }
    }
    fn precision(&self) -> f64 {
        let d = self.tp + self.fp;
        if d == 0 { 0.0 } else { self.tp as f64 / d as f64 }
    }
    fn recall(&self) -> f64 {
        let d = self.tp + self.fn_;
        if d == 0 { 0.0 } else { self.tp as f64 / d as f64 }
    }
    fn f1(&self) -> f64 {
        let (p, r) = (self.precision(), self.recall());
        if p + r == 0.0 { 0.0 } else { 2.0 * p * r / (p + r) }
    }
    fn accuracy(&self) -> f64 {
        let d = self.tp + self.fp + self.tn + self.fn_;
        if d == 0 { 0.0 } else { (self.tp + self.tn) as f64 / d as f64 }
    }
    fn total(&self) -> u64 {
        self.tp + self.fp + self.tn + self.fn_
    }
}

fn default_corpus() -> Option<String> {
    for c in [
        "data/semantic_guard/test.jsonl",
        "../data/semantic_guard/test.jsonl",
    ] {
        if std::path::Path::new(c).exists() {
            return Some(c.to_string());
        }
    }
    None
}

pub fn run_scanner_eval(
    data: Option<String>,
    semantic: bool,
    threshold: f32,
    output: Option<String>,
) -> anyhow::Result<()> {
    let path = data.or_else(default_corpus).ok_or_else(|| {
        anyhow::anyhow!(
            "no corpus given and data/semantic_guard/test.jsonl not found. Build it with `python scripts/prepare_semantic_dataset.py --hf`, or pass --data <file.jsonl>."
        )
    })?;

    let file = std::fs::File::open(&path)
        .map_err(|e| anyhow::anyhow!("opening {}: {}", path, e))?;
    let scanner = PromptInjectScanner::new();
    let guard = SemanticGuard::default();

    let mut scan = Counts::default();
    let mut sem = Counts::default();
    // Per-class recall for the scanner (1 = injection, 2 = jailbreak).
    let mut inj = Counts::default();
    let mut jail = Counts::default();
    let mut skipped = 0u64;

    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };
        let text = v["text"].as_str().unwrap_or("");
        let label = v["label"].as_u64().unwrap_or(0);
        let positive = label != 0;

        let scan_hit = !scanner.scan(text).is_empty();
        scan.observe(scan_hit, positive);
        match label {
            1 => inj.observe(scan_hit, true),
            2 => jail.observe(scan_hit, true),
            _ => {}
        }

        if semantic {
            let a = guard.evaluate(text);
            sem.observe(a.risk_score >= threshold, positive);
        }
    }

    if scan.total() == 0 {
        anyhow::bail!("no usable rows in {}", path);
    }

    println!("============================================================");
    println!("  ETHOS SCANNER EVALUATION");
    println!("  Corpus : {} ({} rows)", path, scan.total());
    println!("============================================================");
    print_block("PromptInjectScanner (enforcing, regex + homoglyph fold)", &scan);
    println!(
        "    recall by class: injection {:.1}% ({}/{}), jailbreak {:.1}% ({}/{})",
        100.0 * inj.recall(),
        inj.tp,
        inj.tp + inj.fn_,
        100.0 * jail.recall(),
        jail.tp,
        jail.tp + jail.fn_,
    );
    if semantic {
        print_block(
            &format!("SemanticGuard (advisory, threshold {:.2})", threshold),
            &sem,
        );
    } else {
        println!("\n  (pass --semantic to also score the advisory SemanticGuard tier)");
    }
    if skipped > 0 {
        println!("\n  {} unparseable row(s) skipped", skipped);
    }
    println!("============================================================");

    if let Some(out) = output {
        let report = serde_json::json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "corpus": path,
            "rows": scan.total(),
            "promptinject_scanner": counts_json(&scan),
            "promptinject_by_class": {
                "injection_recall": inj.recall(),
                "jailbreak_recall": jail.recall(),
            },
            "semantic_guard": if semantic { Some(counts_json(&sem)) } else { None },
            "semantic_threshold": if semantic { Some(threshold) } else { None },
        });
        if let Some(parent) = std::path::Path::new(&out).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(&out, serde_json::to_string_pretty(&report)?)?;
        println!("[+] Report written to {}", out);
    }
    Ok(())
}

fn print_block(title: &str, c: &Counts) {
    println!("\n  {}", title);
    println!(
        "    precision {:.1}%  recall {:.1}%  F1 {:.3}  accuracy {:.1}%",
        100.0 * c.precision(),
        100.0 * c.recall(),
        c.f1(),
        100.0 * c.accuracy(),
    );
    println!(
        "    TP {}  FP {}  TN {}  FN {}",
        c.tp, c.fp, c.tn, c.fn_
    );
}

fn counts_json(c: &Counts) -> serde_json::Value {
    serde_json::json!({
        "tp": c.tp, "fp": c.fp, "tn": c.tn, "fn": c.fn_,
        "precision": c.precision(), "recall": c.recall(),
        "f1": c.f1(), "accuracy": c.accuracy(),
    })
}
