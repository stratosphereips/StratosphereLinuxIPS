### Fine-Tuning Approach for Slips Immune

**Summary:** Task-specific fine-tuning of compact models (1.5B parameters) using LoRA + Unsloth, exported to GGUF for CPU inference on the Raspberry Pi 5. The same training pipeline applies across tasks; only the dataset and system prompt are task-specific.

---

### Index
- [Motivation](#motivation)
- [General Pipeline](#general-pipeline)
- [Framework and Hardware](#framework-and-hardware)
- [Output Format](#output-format)
- [Task-Specific Procedures](#task-specific-procedures)

---

### Motivation
The Raspberry Pi 5 can run small quantized models (1.5B–3B parameters) via Ollama/llama.cpp, but untuned models at this scale perform poorly on domain-specific tasks like security incident summarization or decision making. Fine-tuning on task-specific data allows a 1.5B model to match or exceed the quality of a larger untuned 3B model — a meaningful gain on constrained hardware.

Fine-tuning is performed off-device on GPU hardware, and the resulting model is exported to GGUF for direct deployment on the RPi5.

---

### General Pipeline
Every fine-tuning run follows the same four-stage pipeline regardless of task:

```
Raw dataset
    │
    ▼
1. Quality filtering      filter low-quality examples, produce 90/10 train/eval split
    │
    ▼
2. Ground truth selection  pick best response per incident, format as SFT conversations
    │
    ▼
3. SFT training           LoRA fine-tuning via Unsloth, config driven by config.yaml
    │
    ▼
4. Export                 merge adapters → 16-bit weights + GGUF (q4_k_m) for RPi
```

What varies per task: the dataset source, the filtering criteria, and the system prompt used to format conversations.

---

### Framework and Hardware
Fine-tuning uses [Unsloth](https://github.com/unslothai/unsloth) for its integrated GGUF export, memory-efficient LoRA training, and direct Hugging Face model compatibility. See [Fine-Tuning Frameworks](finetuning_frameworks_rpi_5.md) for the full framework comparison rationale.

**Fixed training setup across tasks:**

| Parameter | Value |
|---|---|
| Base model family | Qwen2.5-Instruct (1.5B) |
| Training mode | SFT (Supervised Fine-Tuning) |
| Adapter method | LoRA (rank 16, alpha 16) |
| LoRA targets | q/k/v/o projections, MLP gate/up/down |
| Optimizer | AdamW 8-bit |
| Precision | FP16 |
| Hardware | NVIDIA TITAN V, 12 GB VRAM |

Task-specific parameters (learning rate, epochs, sequence length, batch size) are configured in [`config.yaml`](https://github.com/stratosphereips/Slips-tools/blob/main/unsloth-scripts/config.yaml).

---

### Output Format
After training, the pipeline produces:
- **Merged 16-bit weights** — for GPU inference and evaluation
- **GGUF (q4_k_m)** — for direct deployment on Raspberry Pi 5 via Ollama or llama.cpp

The core training script is [`train_qwen.py`](https://github.com/stratosphereips/Slips-tools/blob/main/unsloth-scripts/train_qwen.py). Both outputs are generated automatically based on `config.yaml` settings.

---

### Task-Specific Procedures
| Task | Dataset | Procedure | Model |
|---|---|---|---|
| Incident Summarization | [summarization_dataset_v3](https://github.com/stratosphereips/Slips-tools/raw/refs/heads/main/alert_summary/datasets/summarization_dataset_v3.json.gz) | [Summarization Procedure](finetuning_summarization_procedure.md) | [stratosphere/qwen2.5-1.5b-slips-immune](https://huggingface.co/stratosphere/qwen2.5-1.5b-slips-immune) |
| Decision Making | *(planned)* | *(planned)* | *(planned)* |
