import argparse
import json
from pathlib import Path

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer

SYSTEM = "You are Lida, the LidaShield scam-intelligence AI. Be evidence-backed and cautious."


def load_jsonl(path: Path):
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def generate(tokenizer, model, text: str, max_new_tokens: int = 256) -> str:
    messages = [
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": f"Analyze this message:\n{text}"},
    ]
    prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
    with torch.no_grad():
        out = model.generate(**inputs, max_new_tokens=max_new_tokens, do_sample=False)
    return tokenizer.decode(out[0][inputs["input_ids"].shape[-1]:], skip_special_tokens=True)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--base", default="Qwen/Qwen2.5-0.5B-Instruct")
    p.add_argument("--adapter", required=True)
    p.add_argument("--eval", default="sample_eval.jsonl")
    args = p.parse_args()

    tokenizer = AutoTokenizer.from_pretrained(args.base, trust_remote_code=True)
    model = AutoModelForCausalLM.from_pretrained(
        args.base,
        device_map="auto" if torch.cuda.is_available() else None,
        torch_dtype=torch.bfloat16 if torch.cuda.is_available() else None,
        trust_remote_code=True,
    )
    model = PeftModel.from_pretrained(model, args.adapter)
    model.eval()

    total = 0
    hits = 0
    for ex in load_jsonl(Path(args.eval)):
        total += 1
        pred = generate(tokenizer, model, ex["input"])
        ok = ex["expected_verdict"].lower() in pred.lower()
        hits += int(ok)
        print("=" * 80)
        print("INPUT:", ex["input"])
        print("EXPECTED:", ex["expected_verdict"])
        print("PREDICTED:\n", pred)
        print("PASS:", ok)
    print("=" * 80)
    print(f"Accuracy proxy: {hits}/{total} = {hits / max(total, 1):.2%}")


if __name__ == "__main__":
    main()
