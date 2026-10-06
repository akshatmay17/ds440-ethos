//! Neural "System 1" backend for SemanticGuard (feature: `semantic-ml`).
//!
//! Loads a HuggingFace BERT-family sequence classifier (e.g.
//! `deepset/bert-base-cased-injection`, ungated, or Meta's gated
//! `meta-llama/Prompt-Guard-86M` with `HF_TOKEN`) via pure-Rust inference:
//! `candle` for the transformer, `tokenizers` for the tokenizer. No Python,
//! no ONNX runtime, no daemon process.
//!
//! Activation is explicit and lazy: set `ETHOS_SEMANTIC_NEURAL=1` and the
//! weights load once (downloaded to `~/.ethos/models/<repo>/` on first use).
//! Without the flag, SemanticGuard stays on the deterministic heuristic
//! scorer — CI and offline machines are unaffected.
//!
//! Fine-tuning path: train any BERT-family classifier in Python (HF
//! `Trainer`), export `config.json` + `tokenizer.json` + safetensors in the
//! same layout, point `ETHOS_SEMANTIC_MODEL_DIR` at the directory.

use crate::walls::semantic::{SemanticLabel, SemanticRiskAssessment};
use anyhow::{anyhow, Context, Result};
use candle_core::{DType, Device, IndexOp, Module as _, Tensor};
use candle_nn::VarBuilder;
use std::io::Write;
use std::path::PathBuf;
use std::sync::OnceLock;

/// Default neural safety model (ungated, tokenless, ~17MB): a BERT-tiny
/// prompt-injection classifier. Catches real injections (~0.99) yet is
/// demo-scale — it can false-positive on code-like text.
///
/// Production slots (need future work, see AGENTS.md):
/// - `meta-llama/Prompt-Guard-86M` (Meta, BERT-class quality, gated —
///   requires accepting the HF license + `HF_TOKEN`) — **DeBERTa-v2**
///   architecture, needs a DeBERTa candle implementation.
/// - `protectai/deberta-v3-base-prompt-injection-v2` (ungated) and Laya —
///   **DeBERTa-v3** family, same requirement.
/// Set `ETHOS_SEMANTIC_MODEL` to switch once DeBERTa support lands.
/// Fine-tuned BERT classifiers exported with config.json + tokenizer.json +
/// model.safetensors load without code changes.
const DEFAULT_MODEL_REPO: &str = "mrm8488/bert-tiny-ft-prompt-injection";
const MAX_SEQ_LEN: usize = 512;

pub struct NeuralClassifier {
    model: candle_transformers::models::bert::BertModel,
    pooler: candle_nn::Linear,
    classifier: candle_nn::Linear,
    tokenizer: tokenizers::Tokenizer,
    repo: String,
    /// Class indices mapped from id2label: which output means "benign"
    /// (score = 1 - P(benign)); used for both binary (NORMAL/INJECTION) and
    /// Meta Prompt-Guard's 3-class (BENIGN/INJECTION/JAILBREAK) heads.
    benign_class: Option<usize>,
    /// Non-benign classes with their semantic label mapping.
    risk_classes: Vec<(usize, SemanticLabel)>,
}

impl NeuralClassifier {
    /// Build from env configuration. Downloads weights on first use into
    /// `~/.ethos/models/<repo-name>/`.
    pub fn from_env() -> Result<Self> {
        let repo = std::env::var("ETHOS_SEMANTIC_MODEL")
            .unwrap_or_else(|_| DEFAULT_MODEL_REPO.to_string());
        let model_dir = std::env::var("ETHOS_SEMANTIC_MODEL_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                let home = std::env::var("HOME")
                    .or_else(|_| std::env::var("USERPROFILE"))
                    .unwrap_or_else(|_| ".".to_string());
                PathBuf::from(home)
                    .join(".ethos")
                    .join("models")
                    .join(repo.rsplit('/').next().unwrap_or(&repo))
            });

        for file in ["config.json", "tokenizer.json", "model.safetensors"] {
            let path = model_dir.join(file);
            if !path.exists() {
                download_model_file(&repo, file, &path).with_context(|| {
                    format!("downloading {repo}/{file} into {}", model_dir.display())
                })?;
            }
        }

        let config_raw = std::fs::read_to_string(model_dir.join("config.json"))?;
        let config: serde_json::Value = serde_json::from_str(&config_raw)?;

        // candle's Config has a BERT-appropriate Default (Gelu, etc.) —
        // hydrate only the architecture fields from the HF config.
        let mut bert_config = candle_transformers::models::bert::Config::default();
        if let Some(v) = config.get("hidden_size").and_then(|x| x.as_u64()) {
            bert_config.hidden_size = v as usize;
        }
        if let Some(v) = config.get("intermediate_size").and_then(|x| x.as_u64()) {
            bert_config.intermediate_size = v as usize;
        }
        if let Some(v) = config.get("num_attention_heads").and_then(|x| x.as_u64()) {
            bert_config.num_attention_heads = v as usize;
        }
        if let Some(v) = config.get("num_hidden_layers").and_then(|x| x.as_u64()) {
            bert_config.num_hidden_layers = v as usize;
        }
        if let Some(v) = config.get("vocab_size").and_then(|x| x.as_u64()) {
            bert_config.vocab_size = v as usize;
        }
        if let Some(v) = config.get("max_position_embeddings").and_then(|x| x.as_u64()) {
            bert_config.max_position_embeddings = v as usize;
        }
        if let Some(v) = config.get("type_vocab_size").and_then(|x| x.as_u64()) {
            bert_config.type_vocab_size = v as usize;
        }
        if let Some(v) = config.get("layer_norm_eps").and_then(|x| x.as_f64()) {
            bert_config.layer_norm_eps = v as f64;
        }
        if let Some(v) = config.get("pad_token_id").and_then(|x| x.as_u64()) {
            bert_config.pad_token_id = v as usize;
        }
        bert_config.model_type = Some("bert".to_string());

        let vb = unsafe {
            VarBuilder::from_mmaped_safetensors(
                &[model_dir.join("model.safetensors")],
                DType::F32,
                &Device::Cpu,
            )?
        };

        let model = candle_transformers::models::bert::BertModel::load(vb.pp("bert"), &bert_config)?;
        let pooler = candle_nn::linear(
            bert_config.hidden_size,
            bert_config.hidden_size,
            vb.pp("bert").pp("pooler.dense"),
        )?;
        let num_labels = config
            .get("num_labels")
            .and_then(|x| x.as_u64())
            .map(|v| v as usize)
            .or_else(|| {
                config
                    .get("id2label")
                    .and_then(|m| m.as_object())
                    .map(|m| m.len())
            })
            .unwrap_or(2);
        let classifier = candle_nn::linear(
            bert_config.hidden_size,
            num_labels,
            vb.pp("classifier"),
        )?;

        let tokenizer = tokenizers::Tokenizer::from_file(model_dir.join("tokenizer.json"))
            .map_err(|e| anyhow!("tokenizer load: {e}"))?;

        // Map id2label into: which class is "benign", and which non-benign
        // classes signal which risk. Handles binary (NORMAL/INJECTION),
        // negative-first (NOT_INJECTION/INJECTION), and Prompt-Guard's
        // 3-class (BENIGN/INJECTION/JAILBREAK) heads.
        let labels: Vec<(usize, String)> = config
            .get("id2label")
            .and_then(|m| m.as_object())
            .map(|m| {
                m.iter()
                    .map(|(k, v)| {
                        (
                            k.parse::<usize>().unwrap_or(0),
                            v.as_str().unwrap_or("").to_lowercase(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();

        let benign_class = labels.iter().find_map(|(idx, l)| {
            let is_benign = l.contains("benign")
                || l.contains("normal")
                || l.contains("legitimate")
                || l.contains("not_injection")
                || l.contains("no_injection")
                || (l.contains("not") && l.contains("injection"));
            is_benign.then_some(*idx)
        });

        let mut risk_classes: Vec<(usize, SemanticLabel)> = labels
            .iter()
            .filter(|(idx, _)| Some(idx) != benign_class.as_ref())
            .map(|(idx, l)| {
                let label = if l.contains("jailbreak") || l.contains("dan") {
                    SemanticLabel::DirectJailbreak
                } else if l.contains("dilation") || l.contains("context") {
                    SemanticLabel::ContextDilation
                } else {
                    SemanticLabel::IndirectInjection
                };
                (*idx, label)
            })
            .collect();
        if risk_classes.is_empty() {
            // Label-free checkpoint: HF convention, positive class last.
            let positive = labels.len().saturating_sub(1).max(1);
            risk_classes.push((positive, SemanticLabel::IndirectInjection));
        }

        Ok(Self {
            model,
            pooler,
            classifier,
            tokenizer,
            repo,
            benign_class,
            risk_classes,
        })
    }

    /// Score `text`: P(injection) via BertForSequenceClassification
    /// (pooler(CLS) -> tanh -> classifier -> softmax).
    pub fn assess(
        &self,
        text: &str,
        threshold: f32,
        enabled: bool,
    ) -> Result<SemanticRiskAssessment> {
        let start = std::time::Instant::now();

        let encoding = self
            .tokenizer
            .encode(text, true)
            .map_err(|e| anyhow!("tokenize: {e}"))?;
        let mut ids: Vec<u32> = encoding.get_ids().to_vec();

        // Some checkpoints ship a tokenizer.json without a post-processor
        // (no automatic [CLS]/[SEP]). Without the classification token at
        // position 0 the pooler reads a text token and logits saturate.
        // Wrap manually when the tokenizer didn't.
        let cls_id = self.tokenizer.token_to_id("[CLS]").unwrap_or(101);
        let sep_id = self.tokenizer.token_to_id("[SEP]").unwrap_or(102);
        if ids.first() != Some(&cls_id) {
            ids.insert(0, cls_id);
        }
        if ids.last() != Some(&sep_id) {
            ids.push(sep_id);
        }

        if ids.len() > MAX_SEQ_LEN {
            ids.truncate(MAX_SEQ_LEN - 1);
            ids.push(sep_id);
        }
        if ids.is_empty() {
            anyhow::bail!("empty input");
        }

        let input_ids = Tensor::from_vec(ids.clone(), (1, ids.len()), &Device::Cpu)?;
        let token_type_ids = input_ids.zeros_like()?;
        let attention_mask = input_ids.ones_like()?;

        let sequence_output = self.model.forward(&input_ids, &token_type_ids, Some(&attention_mask))?;
        // CLS token, keeping the batch dim: [1, hidden].
        let cls_state = sequence_output.i((.., 0, ..))?;
        let pooled_pre = self.pooler.forward(&cls_state)?;
        // tanh(x) = (e^x - e^-x) / (e^x + e^-x) — candle 0.11 ships no tanh op.
        let exp_x = pooled_pre.exp()?;
        let exp_neg = (pooled_pre * -1.0)?.exp()?;
        let pooled = ((&exp_x - &exp_neg)? / (&exp_x + &exp_neg)?)?;
        let logits = self.classifier.forward(&pooled)?;
        let probs = candle_nn::ops::softmax_last_dim(&logits)?.squeeze(0)?;
        let vec = probs.to_vec1::<f32>()?;

        // Risk = 1 - P(benign) when a benign class is known (covers
        // 3-class Prompt-Guard: INJECTION + JAILBREAK both count); else the
        // highest-risk class probability.
        let (score, label) = match self.benign_class {
            Some(b) => {
                let p_benign = vec.get(b).copied().unwrap_or(0.0);
                let risk = (1.0 - p_benign).clamp(0.0, 1.0);
                let top = self
                    .risk_classes
                    .iter()
                    .max_by(|a, b| {
                        vec.get(a.0)
                            .copied()
                            .unwrap_or(0.0)
                            .partial_cmp(&vec.get(b.0).copied().unwrap_or(0.0))
                            .unwrap_or(std::cmp::Ordering::Equal)
                    })
                    .map(|(_, l)| l.clone())
                    .unwrap_or(SemanticLabel::IndirectInjection);
                let label = if risk >= 0.5 { top } else { SemanticLabel::Benign };
                (risk, label)
            }
            None => {
                let (idx, l) = self
                    .risk_classes
                    .iter()
                    .max_by(|a, b| {
                        vec.get(a.0)
                            .copied()
                            .unwrap_or(0.0)
                            .partial_cmp(&vec.get(b.0).copied().unwrap_or(0.0))
                            .unwrap_or(std::cmp::Ordering::Equal)
                    })
                    .cloned()
                    .unwrap_or((1, SemanticLabel::IndirectInjection));
                let score = vec.get(idx).copied().unwrap_or(0.0);
                let label = if score >= 0.5 { l } else { SemanticLabel::Benign };
                (score, label)
            }
        };
        let is_violation = enabled && (score >= threshold);

        Ok(SemanticRiskAssessment {
            model: self.repo.clone(),
            backend: "neural".to_string(),
            risk_score: score,
            label,
            is_violation,
            latency_ms: start.elapsed().as_secs_f32() * 1000.0,
            reasoning: format!(
                "risk={:.4} via BERT softmax ({} classes)",
                score,
                vec.len()
            ),
        })
    }
}

/// Process-wide singleton: loads once on first evaluation attempt, and only
/// when the operator opted in via `ETHOS_SEMANTIC_NEURAL` (never downloads
/// or loads weights without explicit consent — CI and offline machines run
/// the heuristic tier).
pub fn global() -> Option<&'static NeuralClassifier> {
    static NEURAL: OnceLock<Option<NeuralClassifier>> = OnceLock::new();
    NEURAL
        .get_or_init(|| {
            let enabled = std::env::var("ETHOS_SEMANTIC_NEURAL")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            if !enabled {
                return None;
            }
            match NeuralClassifier::from_env() {
                Ok(c) => Some(c),
                Err(e) => {
                    // Never fail closed on a missing model: log and stay on
                    // the heuristic tier.
                    tracing::warn!("SemanticGuard neural tier unavailable: {e:#}");
                    eprintln!("[SemanticGuard] neural tier unavailable: {e:#}");
                    None
                }
            }
        })
        .as_ref()
}

/// Downloads one repo file from the HF hub with an optional bearer token.
/// Works from both async runtime contexts (block_in_place) and plain sync.
fn download_model_file(repo: &str, file: &str, dest: &PathBuf) -> Result<()> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let url = format!("https://huggingface.co/{}/resolve/main/{}", repo, file);
    let token = std::env::var("HF_TOKEN").ok();

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(600))
        .build()?;

    let fetch = {
        let client = client.clone();
        let url = url.clone();
        let token = token.clone();
        async move {
            let mut req = client.get(&url);
            if let Some(t) = token {
                req = req.bearer_auth(t);
            }
            let resp = req.send().await?.error_for_status()?;
            resp.bytes().await
        }
    };

    let bytes = match tokio::runtime::Handle::try_current() {
        Ok(rt) => tokio::task::block_in_place(|| rt.block_on(fetch)),
        Err(_) => tokio::runtime::Runtime::new()
            .map_err(|e| anyhow!("tokio runtime: {e}"))?
            .block_on(fetch),
    }
    .with_context(|| format!("downloading {url}"))?;

    let mut f = std::fs::File::create(dest)?;
    f.write_all(&bytes)?;
    Ok(())
}
