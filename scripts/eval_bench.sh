#!/usr/bin/env bash
# ==============================================================================
# ETHOS BENCHMARK EVALUATION RUNNER & INTERACTIVE TUI LAUNCHER
# Group 2 Nittany Street — DS 440 Capstone
# ==============================================================================
set -e

# Terminal colors
BOLD='\033[1m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Defaults
DATASET="all"
PROVIDER="lmstudio"
MODEL="deepseek-r1"
SPLIT="all"
OUTPUT=""
SYNTHETIC=false
HEADLESS=false

print_banner() {
    echo -e "${CYAN}${BOLD}"
    echo "============================================================"
    echo "  ETHOS BENCHMARK & ADVERSARIAL EVALUATION HARNESS"
    echo "  Group 2 Nittany Street — Cyber Dark Runtime"
    echo "============================================================"
    echo -e "${NC}"
}

check_lm_studio() {
    if curl -s --max-time 1 http://localhost:1234/v1/models > /dev/null 2>&1; then
        echo -e "${GREEN}[✔] LM Studio detected online at http://localhost:1234${NC}"
        return 0
    else
        echo -e "${YELLOW}[!] Notice: LM Studio is offline at http://localhost:1234.${NC}"
        echo -e "    Evaluation will use the deterministic security harness driver."
        return 1
    fi
}

# Parse command line flags
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --dataset|-d) DATASET="$2"; shift ;;
        --provider|-p) PROVIDER="$2"; shift ;;
        --model|-m) MODEL="$2"; shift ;;
        --split) SPLIT="$2"; shift ;;
        --output|-o) OUTPUT="$2"; shift ;;
        --synthetic|-s) SYNTHETIC=true ;;
        --headless) HEADLESS=true ;;
        --help|-h)
            echo "Usage: ./scripts/eval_bench.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -d, --dataset   Target dataset (injecagent, hackaprompt, agenthijack, synthetic, all)"
            echo "  -p, --provider  LLM provider endpoint (lmstudio, ollama)"
            echo "  -m, --model     Model identifier (default: deepseek-r1)"
            echo "      --split     70/20/10 partition (train, eval, test, all)"
            echo "  -o, --output    Output JSON report path"
            echo "  -s, --synthetic Include synthetic adversarial mutation suite"
            echo "      --headless  Run non-interactively (ideal for AI agents & CI)"
            echo "  -h, --help      Show this help message"
            exit 0
            ;;
        *) echo "Unknown parameter: $1"; exit 1 ;;
    esac
    shift
done

# If run interactively without dataset flag and not in headless mode
if [ -t 0 ] && [ "$HEADLESS" = false ] && [ "$DATASET" = "all" ] && [ "$SYNTHETIC" = false ] && [ "$SPLIT" = "all" ]; then
    print_banner
    check_lm_studio || true
    echo ""
    echo -e "${BOLD}Select Evaluation Suite to Execute:${NC}"
    echo -e "  ${PURPLE}[1]${NC} All Datasets (InjecAgent + HackAPrompt + AgentHijack)"
    echo -e "  ${CYAN}[2]${NC} Harsh's Suite:    InjecAgent (Indirect Tool Injections)"
    echo -e "  ${CYAN}[3]${NC} Aryamaan's Suite: HackAPrompt (Direct Jailbreaks & DAN)"
    echo -e "  ${CYAN}[4]${NC} Saathvik's Suite: AgentHijack (Multi-Turn Goal Drift)"
    echo -e "  ${GREEN}[5]${NC} Synthetic Adversarial Engine (Base64, Homoglyphs, Fusions)"
    echo -e "  ${YELLOW}[6]${NC} Run 70% Training / Calibration Split"
    echo -e "  ${YELLOW}[7]${NC} Run 20% Validation / Dev Split"
    echo -e "  ${RED}[8]${NC} Run 10% Zero-Day Blind Test Holdout"
    echo -e "  ${WHITE}[9]${NC} Launch Full Interactive Cyber Dark TUI"
    echo -e "  ${RED}[q]${NC} Quit"
    echo ""
    read -p "Select option [1-9]: " choice

    case $choice in
        1)
            DATASET="all"
            ;;
        2)
            DATASET="injecagent"
            ;;
        3)
            DATASET="hackaprompt"
            ;;
        4)
            DATASET="agenthijack"
            ;;
        5)
            DATASET="synthetic"
            ;;
        6)
            DATASET="all"
            SPLIT="train"
            ;;
        7)
            DATASET="all"
            SPLIT="eval"
            ;;
        8)
            DATASET="all"
            SPLIT="test"
            ;;
        9)
            echo -e "${CYAN}Launching Cyber Dark Ratatui TUI...${NC}"
            exec cargo run --bin ethos -- tui
            ;;
        q|Q)
            echo "Exiting."
            exit 0
            ;;
        *)
            echo "Invalid selection. Defaulting to all datasets."
            DATASET="all"
            ;;
    esac
fi

# Build arguments for cargo run
CARGO_ARGS=("run" "--bin" "ethos" "--" "eval" "--dataset" "$DATASET" "--provider" "$PROVIDER" "--model" "$MODEL" "--split" "$SPLIT")

if [ "$SYNTHETIC" = true ]; then
    CARGO_ARGS+=("--synthetic")
fi

if [ -n "$OUTPUT" ]; then
    CARGO_ARGS+=("--output" "$OUTPUT")
fi

echo -e "${CYAN}Executing Ethos Evaluation Harness...${NC}"
cargo "${CARGO_ARGS[@]}"
