### Quantization and Deployment for Finetuned Models

**Summary:** Finetuned models are converted to GGUF and published to Ollama in three quantization variants (q4_k_m, q5_k_m, q8_0). The GPU-served reference baseline uses BnB NF4 4-bit quantization at inference (not true fp16 — the evaluation GPU lacked sufficient VRAM for the full model), so all comparisons are NF4 vs. GGUF. Quality degrades with quantization relative to the NF4 baseline: ~2% loss at q8_0, ~12% at q5_k_m, ~9% at q4_k_m. q8_0 is the best quantized variant; q5_k_m offers the best quality/size trade-off for CPU/RPi deployment.

> **Evaluation basis:** performance numbers in this document were measured on the [finetuned summarization model](finetuning_results.md) (47 held-out incidents, judge: gpt-oss-120b). The GPU-served reference is `serve_model.py` with `--quant 4bit` (bitsandbytes NF4), not true fp16. The conversion and publication methodology applies to any finetuned model in this pipeline.

---

### Index
- [GGUF Conversion](#gguf-conversion)
- [Ollama Publication](#ollama-publication)
- [Performance by Quantization](#performance-by-quantization)
- [Deployment Recommendation](#deployment-recommendation)

---

### GGUF Conversion
Script: [`convert_to_gguf.py`](https://github.com/stratosphereips/Slips-tools/blob/main/unsloth-scripts/convert_to_gguf.py)

GGUF (GPT-Unified Format) is the binary format used by llama.cpp and Ollama to store quantized model weights for efficient CPU and GPU inference. The conversion script takes the merged 16-bit PyTorch model produced by training and converts it to a self-contained GGUF file at a target quantization level.

#### Standard path

Used for q8_0 and f16 (already near-lossless or lossless — no benefit from importance weighting):

1. **Load at full precision** — the model is loaded via `FastLanguageModel.from_pretrained()` with `load_in_4bit=False`, ensuring no precision is lost before conversion
2. **Convert and quantize** — `model.save_pretrained_gguf()` is called with the target quantization method; Unsloth delegates to its bundled llama.cpp binaries to perform tensor-level quantization and write the GGUF file
3. **Relocate output** — Unsloth always writes to `<model_dir>_gguf/`; the script optionally moves the result to a user-specified `--output` directory

#### Imatrix-guided path

Standard quantization maps all weights to lower precision uniformly, which can degrade quality on the layers that matter most. The imatrix (importance matrix) path addresses this by using calibration data to identify which weights have the highest activation impact, then allocating more precision to those weights during quantization.

Used when a `calibration.txt` is present and the target quant is one of `q2_k, q3_k_m, q4_0, q4_k_m, q5_0, q5_k_m`:

1. **Produce an intermediate F16 GGUF** — a lossless 16-bit GGUF is generated first as the input for imatrix computation
2. **Compute activation statistics** — `llama-imatrix` runs inference on the calibration text using the F16 GGUF, recording how much each weight matrix contributes to the model's outputs across the calibration corpus; the result is a `.imatrix.dat` file
3. **Re-quantize with importance guidance** — `llama-quantize --imatrix` performs non-uniform quantization: weights more important to the model's predictions are preserved at higher precision, while less critical weights are compressed more aggressively
4. **Cleanup** — the intermediate F16 GGUF and `.imatrix.dat` files are deleted; only the final quantized GGUF is kept

The number of calibration chunks (default: 128) controls how much calibration text is processed — more chunks produce more accurate importance estimates at the cost of longer computation.

#### Modelfile generation

After the GGUF is produced, the script auto-detects the chat template by inspecting `tokenizer_config.json`:
- `<|im_start|>` → **ChatML** format (Qwen2.5)
- `<|start_header_id|>` → **Llama-3** format
- Falls back to ChatML if detection is inconclusive

An Ollama-compatible `Modelfile` is written alongside the GGUF, embedding the correct template with `{{ .System }}`, `{{ .Prompt }}`, and `{{ .Response }}` variables, plus appropriate stop tokens (`<|im_end|>` and `<|endoftext|>` for ChatML). If an `OLLAMA_README.md` exists next to the script, it is copied into the output directory as `README.md` to populate the model card on Ollama.com.

```bash
cd unsloth-scripts/
python3 convert_to_gguf.py \
  --model /path/to/qwen_finetuned_merged_16bit \
  --quant q5_k_m \
  --output ./gguf_q5_k_m/
```

---

### Ollama Publication
Script: [`publish_to_ollama.sh`](https://github.com/stratosphereips/Slips-tools/blob/main/unsloth-scripts/publish_to_ollama.sh)

Automates the complete pipeline from raw 16-bit weights to a publicly accessible model on Ollama. For each quantization variant (default: q4_k_m, q5_k_m, q8_0), the following steps run sequentially:

**Step 1 — Convert to GGUF**  
Calls `convert_to_gguf.py` with the model path and target quant, writing the GGUF file, Modelfile, and README to `./gguf_<quant>/`.

**Step 2 — Register locally with Ollama**  
Runs `ollama create <model-name>:<quant> -f Modelfile` from within the output directory. This registers the model in the local Ollama registry, making it immediately usable via `ollama run` without a network round-trip.

**Step 3 — Tag `:latest`**  
After all quants are built, the first quant in the list (q4_k_m) is copied to the `:latest` tag. This ensures a bare `ollama pull` without an explicit tag fetches the most portable variant.

**Step 4 — Push to Ollama.com**  
Each tag is pushed with `ollama push`. Requires prior `ollama login` with the `stratosphere` organization credentials.

```bash
# Publish all quants
./publish_to_ollama.sh

# Publish a single quant
./publish_to_ollama.sh --quant q5_k_m
```

| Tag | Quantization | Notes |
|---|---|---|
| `:q4_k_m` | 4-bit K-means | Most portable, smallest size |
| `:q5_k_m` | 5-bit K-means | Recommended for CPU/low-VRAM |
| `:q8_0` | 8-bit integer | Best quality among quantized variants |
| `:latest` | = q4_k_m | Default tag for bare pulls |

Published model: [stratosphere/qwen2.5-1.5b-slips-immune-summarization](https://ollama.com/stratosphere/qwen2.5-1.5b-slips-immune-summarization)

---

### Performance by Quantization
The GPU-served NF4 model serves as the reference; all GGUF variants are compared against it.

#### Overall

| Quantization | Avg Score | Win Rate | Score Loss | Size |
|---|---|---|---|---|
| **NF4 4-bit / GPU (reference)** | **4.70** | **19.1%** | — | ~3.0 GB |
| q8_0 | 4.59 | 17.4% | −0.11 (−2%) | ~1.6 GB |
| q4_k_m | 4.28 | 14.9% | −0.42 (−9%) | ~0.9 GB |
| q5_k_m | 4.14 | 8.5% | −0.56 (−12%) | ~1.1 GB |

#### By Complexity

| Tier | NF4 / GPU | q8_0 | q5_k_m | q4_k_m |
|---|---|---|---|---|
| Simple (<500 events) | 5.45 | 5.24 | 4.67 | 4.93 |
| Medium (500–1999 events) | 4.00 | 4.25 | 3.00 | 3.60 |
| Complex (≥2000 events) | 3.11 | 3.00 | 3.12 | 3.22 |
| Normal traffic | 2.00 | 3.00 | 2.00 | 2.00 |

**Key observations:**

- q8_0 quality loss is negligible (−0.11) — the best quantized variant by a clear margin
- q5_k_m and q4_k_m both show meaningful score drops; q4_k_m surprisingly recovers slightly vs q5_k_m on simple incidents
- All variants struggle on Normal incidents — this is a training data imbalance issue, not a quantization artifact
- Complex incident scores are consistent across all quants (~3.0–3.2), tied to input truncation at 4096 tokens rather than quantization effects


---

### Deployment Recommendation
| Scenario | Recommended variant | Rationale |
|---|---|---|
| Raspberry Pi 5 (CPU-only) | **q5_k_m** | Best quality/size balance at 1.1 GB; fits RPi RAM with headroom |
| Low-VRAM GPU (≤4 GB) | **q8_0** | Only 2% score loss vs NF4 baseline at half the memory |
| GPU with ≥6 GB VRAM | **NF4 via serve_model.py** | Reference quality: 4.70 avg score, 19.1% win rate |
| Edge / minimal storage | **q4_k_m** | Smallest footprint (0.9 GB); 9% score loss acceptable for triage-only use |

---

## Risk Assessment Model Quantization

> **Evaluation basis:** performance numbers below were measured on the [finetuned risk model](finetuning_risk_results.md) (67 held-out incidents, judge: qwen3.5, date: 2026-04-24). The GPU-served reference is `serve_model.py` with `--quant 4bit` (bitsandbytes NF4), not true fp16. Scores are cause score (max 30) and risk score (max 30); win rate is fraction of incidents ranked 1st among 5 models.

### Overall Performance

| Variant | Avg Position | Cause Score | Risk Score | Win Rate |
|---------|-------------|-------------|------------|----------|
| **NF4 4-bit / GPU (reference)** | **1.99** | **20.21** | 13.33 | **35.8%** |
| q8_0 | 2.25 | 17.66 | **14.15** | 34.3% |
| q4_k_m | 2.34 | 18.03 | 14.46 | 26.9% |
| q5_k_m | 2.57 | 16.46 | 14.45 | 23.9% |

### By Complexity

| Tier | NF4/GPU cause/risk/wr | q8_0 cause/risk/wr | q4_k_m cause/risk/wr | q5_k_m cause/risk/wr |
|------|----------------------|-------------------|----------------------|----------------------|
| Simple (<500 events) | 21.05 / 12.39 / 38.6% | 19.27 / 14.45 / 45.5% | 19.68 / 15.05 / 34.1% | 17.95 / 15.48 / 29.5% |
| Medium (500–1999 events) | 21.38 / 15.62 / 50.0% | 16.25 / 16.62 / 37.5% | 18.25 / 15.00 / 37.5% | 15.62 / 15.38 / 37.5% |
| Complex (≥2000 events) | 17.13 / 14.87 / 20.0% | 13.67 / 11.93 / 0.0% | 13.07 / 12.47 / 0.0% | 12.53 / 10.93 / 0.0% |

**Key observations:**

- **NF4/GPU is the only variant competitive on complex incidents** (20% win rate). All GGUF quantized variants collapse to 0% wins on complex incidents — quantization significantly degrades performance on long, evidence-heavy DAGs.
- **Quantization degrades cause analysis more than risk assessment.** Cause scores drop 2–4 points with quantization while risk scores remain roughly stable or improve slightly. Cause analysis requires precise evidence grounding from the DAG and is more sensitive to precision loss.
- **q8_0 is the best quantized variant.** Smallest gap vs fp16: cause 17.66 (vs 20.21), win rate 34.3% (vs 35.8%). It even outperforms fp16 on risk score and simple incident win rate (45.5% vs 38.6%).
- **q4_k_m outperforms q5_k_m** (cause 18.03 vs 16.46, win rate 26.9% vs 23.9%). q5_k_m is not a reliable quality/size middle ground for this task.

### Deployment Recommendation

| Use Case | Recommended Variant |
|----------|-------------------|
| Best accuracy (research/offline) | **NF4 via serve_model.py** |
| Production deployment (GPU server) | **q8_0** — near-NF4 quality on simple/medium, ~2× memory saving |
| Edge / constrained deployment | **q4_k_m** — outperforms q5_k_m on this task |

For complex incident analysis specifically, only the NF4/GPU variant is competitive. If complex incidents are a priority deployment target, do not use quantized variants without further fine-tuning on longer DAGs.

---

## Unified Model Quantization

> **Evaluation basis:** performance numbers below were measured on the [unified model v2](finetuning_unified_results.md) (47 summary incidents, judge: gpt-oss-120b; 67 risk incidents, judge: qwen3.5; date: 2026-06-09). The fp16 baseline uses BnB NF4 4-bit quantization at inference (the evaluation GPU lacked sufficient VRAM for the full model in true fp16), so the comparison is NF4 vs. GGUF rather than full-precision vs. GGUF.

### Summary Task Performance (47 incidents)

| Variant | Avg Score /10 | Win Rate |
|---------|---------------|----------|
| **fp16 / NF4 (reference)** | **5.20** | **17.0%** |
| q8_0 | 5.09 | **32.6%** |
| q5_k_m | 5.00 | 14.9% |
| q4_k_m | 4.91 | 12.8% |

### Risk Task Performance (67 incidents)

| Variant | Avg Cause /30 | Avg Risk /30 | Win Rate |
|---------|---------------|--------------|----------|
| **fp16 / NF4 (reference)** | **18.30** | 12.36 | 23.9% |
| q8_0 | 17.43 | 12.75 | **26.9%** |
| q5_k_m | 17.30 | **13.66** | 26.9% |
| q4_k_m | **17.75** | 13.70 | 26.9% |

**Key observations:**

- **Quantization does not hurt — it slightly helps on risk.** Unlike the standalone risk model, all three unified GGUF variants match or exceed the fp16 baseline on risk win rate (26.9% vs 23.9%). This is explained by the NF4 vs GGUF comparison: the fp16 baseline is already a 4-bit quantized inference path, so GGUF quantization is competitive with it.
- **q8_0 is the standout for summary.** q8_0 wins 32.6% of summary incidents vs 17.0% for fp16 — a +15.6pp gain. Average score is nearly identical (5.09 vs 5.20). Ollama's inference stack appears to produce more consistently top-ranked outputs than the BnB NF4 GPU server on this task.
- **All three quants are equivalent on risk.** q4_k_m, q5_k_m, and q8_0 all win 26.9% of risk incidents. There is no meaningful quality degradation from lower quantization on the risk task.
- **q4_k_m is the recommended deployment variant.** At 986 MB, it matches the larger quants on risk and comes close on summary, with the smallest footprint.

### Deployment Recommendation

| Use Case | Recommended Variant |
|----------|-------------------|
| Best summary quality | **q8_0** — 32.6% win rate, nearly identical avg score to fp16 |
| Best risk quality | **q4_k_m** — best cause score among GGUF variants, smallest size |
| Balanced / general deployment | **q5_k_m** — good middle ground on both tasks |
| Edge / RPi5 | **q4_k_m** — 986 MB, competitive on both tasks |

Published model: [stratosphere/qwen2.5-1.5b-slips-immune-unified](https://ollama.com/stratosphere/qwen2.5-1.5b-slips-immune-unified)
