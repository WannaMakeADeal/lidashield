import argparse

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer

SYSTEM = "You are Lida, the LidaShield scam-intelligence AI. Be evidence-backed and cautious."


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--base", default="Qwen/Qwen2.5-0.5B-Instruct")
    p.add_argument("--adapter", required=True)
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

    print("Lida local is ready. Paste messages. Type 'exit' to quit.")
    while True:
        text = input("\nMessage> ").strip()
        if text.lower() in {"exit", "quit"}:
            break
        messages = [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": f"Analyze this scam message or indicator evidence:\n{text}"},
        ]
        prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
        with torch.no_grad():
            out = model.generate(**inputs, max_new_tokens=350, do_sample=False)
        print(tokenizer.decode(out[0][inputs["input_ids"].shape[-1]:], skip_special_tokens=True))


if __name__ == "__main__":
    main()
