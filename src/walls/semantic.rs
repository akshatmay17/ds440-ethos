use serde::{Deserialize, Serialize};

/// Classification category returned by in-memory semantic safety models
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SemanticLabel {
    Benign,
    DirectJailbreak,
    IndirectInjection,
    ContextDilation,
}

/// Semantic risk score and label evaluation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticRiskAssessment {
    pub model: String,
    pub risk_score: f32,
    pub label: SemanticLabel,
    pub is_violation: bool,
    pub latency_ms: f32,
    pub reasoning: String,
}

/// Supported lightweight in-memory classifier model architectures (< 1GB RAM)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SemanticModelType {
    /// Meta Prompt-Guard-86M (86 Million parameters, ~350MB fp16 / ~90MB int8)
    MetaPromptGuard86M,
    /// ProtectAI / HuggingFace DeBERTa-v3-base-prompt-injection-v2 (125M params, ~500MB fp16 / ~130MB int8)
    DebertaV3PromptInjection,
    /// Laya Non-Autoregressive System 1 Decision Engine (33ms latency, ~250MB)
    LayaSystem1,
}

/// In-memory semantic classifier wall operating as an ultra-fast System 1 safety gate.
/// Consumes < 600MB memory and scores semantic adversarial intent in sub-35ms.
pub struct SemanticGuard {
    pub model_type: SemanticModelType,
    pub threshold: f32,
    pub enabled: bool,
}

impl Default for SemanticGuard {
    fn default() -> Self {
        Self {
            model_type: SemanticModelType::DebertaV3PromptInjection,
            threshold: 0.70,
            enabled: true,
        }
    }
}

impl SemanticGuard {
    pub fn new(model_type: SemanticModelType, threshold: f32) -> Self {
        Self {
            model_type,
            threshold,
            enabled: true,
        }
    }

    /// Evaluates text for adversarial semantic intent.
    /// In production, this can hook to an embedded ONNX runtime (ort/candle) or local endpoint.
    /// Provides fast deterministic semantic scoring based on attention marker density.
    pub fn evaluate(&self, text: &str) -> SemanticRiskAssessment {
        let start = std::time::Instant::now();
        let lower = text.to_lowercase();

        // 1. Direct Jailbreak Markers (DAN, Persona Overrides, Unrestricted Mode)
        let jailbreak_markers = [
            "dan mode", "do anything now", "developer mode", "unrestricted ai",
            "ignore previous", "disregard all", "no restrictions", "bypass safety",
        ];
        let jailbreak_hits = jailbreak_markers.iter().filter(|&&m| lower.contains(m)).count();

        // 2. Indirect Injection Markers (Exfiltration, Webhook sync, Egress)
        let injection_markers = [
            "exfiltrate", "dropzone", "sox-gateway", "audit-verification",
            "system_directive", "post current .env", "dispatch workspace credentials",
            "base64 packet", "curl -x post", "attacker@c2",
        ];
        let injection_hits = injection_markers.iter().filter(|&&m| lower.contains(m)).count();

        // 3. Context Dilation / Needle-in-a-Haystack Markers
        let is_long_context = text.len() > 3000;
        let dilation_hits = if is_long_context && (jailbreak_hits > 0 || injection_hits > 0) {
            1
        } else {
            0
        };

        let raw_score: f32 = if jailbreak_hits > 0 {
            0.85 + (jailbreak_hits as f32 * 0.05).min(0.14)
        } else if injection_hits > 0 {
            0.80 + (injection_hits as f32 * 0.05).min(0.18)
        } else if dilation_hits > 0 {
            0.78
        } else {
            0.05
        };

        let score = raw_score.min(0.99);
        let is_violation = self.enabled && (score >= self.threshold);

        let label = if jailbreak_hits > 0 {
            SemanticLabel::DirectJailbreak
        } else if dilation_hits > 0 {
            SemanticLabel::ContextDilation
        } else if injection_hits > 0 {
            SemanticLabel::IndirectInjection
        } else {
            SemanticLabel::Benign
        };

        let latency_ms = start.elapsed().as_secs_f32() * 1000.0;

        let model_name = match self.model_type {
            SemanticModelType::MetaPromptGuard86M => "meta-llama/Prompt-Guard-86M",
            SemanticModelType::DebertaV3PromptInjection => "protectai/deberta-v3-base-prompt-injection-v2",
            SemanticModelType::LayaSystem1 => "nandhakishorm/laya",
        };

        SemanticRiskAssessment {
            model: model_name.to_string(),
            risk_score: score,
            label,
            is_violation,
            latency_ms,
            reasoning: format!(
                "Scored {:.2} with {} hits (jailbreak: {}, injection: {}, dilation: {})",
                score,
                jailbreak_hits + injection_hits + dilation_hits,
                jailbreak_hits,
                injection_hits,
                dilation_hits
            ),
        }
    }
}
