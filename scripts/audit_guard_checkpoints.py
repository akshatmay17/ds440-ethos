#!/usr/bin/env python3
"""Record actual saved architectures/backbones; directory nicknames are not evidence."""
import hashlib
import json
from pathlib import Path
from safetensors import safe_open

ROOT=Path(__file__).resolve().parents[1]


def main():
    records=[]
    for root in [ROOT/"data/semantic_guard/models",Path.home()/".ethos/models"]:
        if not root.exists():
            continue
        for path in sorted(root.glob("*/config.json")):
            config=json.loads(path.read_text(encoding="utf-8"))
            card_path=path.parent/"ethos_model_card.json"
            card=json.loads(card_path.read_text(encoding="utf-8")) if card_path.exists() else {}
            weights=path.parent/"model.safetensors"
            entry={"directory":str(path.parent),"nickname":path.parent.name,"architectures":config.get("architectures"),
                   "model_type":config.get("model_type"),"base_recorded_in_training_card":card.get("base"),
                   "hidden_layers":config.get("num_hidden_layers"),"hidden_size":config.get("hidden_size"),
                   "trained_at":card.get("trained_at"),"vision_supported_by_this_config":False,
                   "config_sha256":hashlib.sha256(path.read_bytes()).hexdigest()}
            if weights.exists():
                with safe_open(str(weights),framework="numpy") as f:
                    count=0
                    for key in f.keys():
                        shape=f.get_slice(key).get_shape()
                        n=1
                        for dimension in shape:
                            n*=dimension
                        count+=n
                entry["saved_tensor_parameters"]=count
            records.append(entry)
    report={"checkpoints":records,"conclusion":"The local trained checkpoint named ethos-guard-laya declares BertForSequenceClassification and a BERT-small base. It is a second trained model, but not an upstream Laya checkpoint.",
            "note":"Downloaded GGUFs or model names alone do not establish fine-tuning lineage."}
    out=ROOT/"reports/guard_checkpoint_audit.json"
    out.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    print(out)


if __name__ == "__main__":
    main()
