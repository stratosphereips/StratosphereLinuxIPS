### Quantization and Deployment for Finetuned Models

**Summary:** Finetuned models are converted to GGUF and published to Ollama in three quantization variants (q4_k_m, q5_k_m, q8_0). Quality degrades gracefully: ~5% loss at q8_0, ~13% at q4_k_m, ~13% at q5_k_m. q8_0 is the best quantized variant; q5_k_m offers the best quality/size trade-off for CPU/RPi deployment; 16-bit is recommended when a GPU is available.

> **Evaluation basis:** performance numbers in this document were measured on the [finetuned summarization model](finetuning_results.md) (47 held-out incidents, judge: gpt-oss-120b). The conversion and publication methodology applies to any finetuned model in this pipeline.

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

---

### Performance by Quantization
The 16-bit model serves as the reference; all GGUF variants are compared against it.

#### Overall

| Quantization | Avg Score | Win Rate | Score Loss | Size |
|---|---|---|---|---|
| **16bit (reference)** | **4.81** | **21.3%** | — | ~3.0 GB |
| q8_0 | 4.58 | 17.0% | −0.23 (−5%) | ~1.6 GB |
| q5_k_m | 4.17 | 2.1% | −0.64 (−13%) | ~1.1 GB |
| q4_k_m | 3.96 | 12.8% | −0.85 (−18%) | ~0.9 GB |

#### By Complexity

| Tier | 16bit | q8_0 | q5_k_m | q4_k_m |
|---|---|---|---|---|
| Simple (<500 events) | 5.39 | 5.13 | 4.70 | 4.55 |
| Medium (500–1999 events) | 4.33 | 4.14 | 2.71 | 3.00 |
| Complex (≥2000 events) | 3.33 | 2.88 | 3.62 | 2.78 |
| Normal traffic | 1.50 | 4.50 | 2.00 | 2.00 |

**Key observations:**

- Quality degrades gracefully across levels with no abrupt collapse between steps
- All quantized variants show better compression (0.19–0.20) than the 16-bit model (0.36), producing more concise outputs but with fewer abstracted bullets — they summarize more aggressively but paraphrase less
- All variants struggle on Normal incidents — this mirrors the 16-bit model's own weakness (1.50) and is a training data imbalance issue, not a quantization artifact
- Complex incident degradation is consistent across all quants, tied to the input truncation ceiling above ~4000 events


---

### Deployment Recommendation
| Scenario | Recommended variant | Rationale |
|---|---|---|
| Raspberry Pi 5 (CPU-only) | **q5_k_m** | Best quality/size balance at 1.1 GB; fits RPi RAM with headroom |
| Low-VRAM GPU (≤4 GB) | **q8_0** | Only 19% score loss at half the size of 16-bit |
| GPU with ≥6 GB VRAM | **16-bit** | Reference quality: 4.81 avg score, 21.3% win rate |
| Edge / minimal storage | **q4_k_m** | Smallest footprint (0.9 GB); 33% score loss acceptable for triage-only use |
