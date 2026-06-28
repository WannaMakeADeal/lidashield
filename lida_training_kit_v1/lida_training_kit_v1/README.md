# Lida Training Kit v1

This kit fine-tunes an open-source LLM into **Lida**, a scam-intelligence analyst for LidaShield.

Important: do not train on secrets. Do not put Supabase passwords, Stripe keys, Google secrets, or `.env` files into datasets or GitHub.

## What this kit does

1. Pulls defensive training examples from your LidaShield database, if `DATABASE_URL` is set.
2. Converts reports, intelligence events, AI analyst observations, and feedback into SFT JSONL.
3. Fine-tunes an open-source chat model with LoRA/QLoRA.
4. Runs a simple evaluation before you trust the model.

## Recommended models

Start small, then scale:

- Fast sanity test: `Qwen/Qwen2.5-0.5B-Instruct`
- Better first Lida: `Qwen/Qwen2.5-1.5B-Instruct`
- Serious Lida: `Qwen/Qwen2.5-7B-Instruct`
- Alternative: `mistralai/Mistral-7B-Instruct-v0.3`

## Folder contents

- `requirements-lida-train.txt` — install dependencies
- `lida_system_prompt.txt` — Lida identity and rules
- `make_lida_dataset.py` — build training data from DB or sample file
- `train_lida_qlora.py` — LoRA/QLoRA fine-tune script
- `eval_lida.py` — basic evaluation against labelled cases
- `run_lida_local.py` — run your trained adapter locally
- `sample_lida_sft.jsonl` — starter examples
- `sample_eval.jsonl` — starter evaluation cases

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
pip install -r requirements-lida-train.txt
```

Build dataset from sample:

```bash
python make_lida_dataset.py --sample-only --out data/lida_sft.jsonl
```

Train small sanity model:

```bash
python train_lida_qlora.py --model Qwen/Qwen2.5-0.5B-Instruct --data data/lida_sft.jsonl --out models/lida-qwen-0.5b-lora --epochs 1
```

Train stronger model if you have GPU:

```bash
python train_lida_qlora.py --model Qwen/Qwen2.5-7B-Instruct --data data/lida_sft.jsonl --out models/lida-qwen-7b-lora --epochs 2 --qlora
```

Run locally:

```bash
python run_lida_local.py --base Qwen/Qwen2.5-0.5B-Instruct --adapter models/lida-qwen-0.5b-lora
```

Evaluate:

```bash
python eval_lida.py --base Qwen/Qwen2.5-0.5B-Instruct --adapter models/lida-qwen-0.5b-lora --eval sample_eval.jsonl
```

## Build dataset from LidaShield DB

Set DATABASE_URL locally only:

```bash
export DATABASE_URL='postgresql://...'
python make_lida_dataset.py --out data/lida_sft_from_db.jsonl
```

Never commit `DATABASE_URL` to GitHub.

## The Lida rule

Lida must be an evidence-backed scam analyst, not a hallucinating chatbot.

Every answer should prefer:

- extracted indicators
- database evidence
- intelligence events
- duplicate report history
- false-positive caution
- recommended safe action

Never teach users how to run scams.
