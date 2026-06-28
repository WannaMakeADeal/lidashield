import argparse
import os

import torch
from datasets import load_dataset
from peft import LoraConfig
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from trl import SFTConfig, SFTTrainer


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--model", default="Qwen/Qwen2.5-0.5B-Instruct")
    p.add_argument("--data", default="data/lida_sft.jsonl")
    p.add_argument("--out", default="models/lida-lora")
    p.add_argument("--epochs", type=float, default=1.0)
    p.add_argument("--lr", type=float, default=1e-4)
    p.add_argument("--batch", type=int, default=1)
    p.add_argument("--grad-accum", type=int, default=8)
    p.add_argument("--max-seq", type=int, default=1536)
    p.add_argument("--qlora", action="store_true")
    args = p.parse_args()

    os.makedirs(args.out, exist_ok=True)

    dataset = load_dataset("json", data_files=args.data, split="train")
    tokenizer = AutoTokenizer.from_pretrained(args.model, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    quant_config = None
    if args.qlora:
        quant_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_use_double_quant=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16 if torch.cuda.is_available() else torch.float32,
        )

    model = AutoModelForCausalLM.from_pretrained(
        args.model,
        device_map="auto" if torch.cuda.is_available() else None,
        quantization_config=quant_config,
        torch_dtype=torch.bfloat16 if torch.cuda.is_available() and not args.qlora else None,
        trust_remote_code=True,
    )

    peft_config = LoraConfig(
        r=16,
        lora_alpha=32,
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    )

    train_args = SFTConfig(
        output_dir=args.out,
        num_train_epochs=args.epochs,
        learning_rate=args.lr,
        per_device_train_batch_size=args.batch,
        gradient_accumulation_steps=args.grad_accum,
        max_seq_length=args.max_seq,
        logging_steps=5,
        save_strategy="epoch",
        packing=False,
        assistant_only_loss=True,
        bf16=torch.cuda.is_available(),
        report_to=[],
    )

    trainer = SFTTrainer(
        model=model,
        args=train_args,
        train_dataset=dataset,
        peft_config=peft_config,
        tokenizer=tokenizer,
    )
    trainer.train()
    trainer.save_model(args.out)
    tokenizer.save_pretrained(args.out)
    print(f"Saved Lida LoRA adapter to {args.out}")


if __name__ == "__main__":
    main()
