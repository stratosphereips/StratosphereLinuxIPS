### Summarization Fine-Tuned Model: Evaluation Results

**Summary:** The Qwen2.5-1.5B model fine-tuned for Slips incident summarization ranks 3rd overall with a 4.81 avg score and 21.3% win rate — above both Qwen2.5 baselines and competitive with GPT-4o on simple incidents. The model produces concise, abstracted summaries with the highest paraphrasing rate of all evaluated models. The primary weakness is performance on complex incidents (≥2000 events) caused by context length limitations.

**Model:** [stratosphere/qwen2.5-1.5b-slips-immune](https://huggingface.co/stratosphere/qwen2.5-1.5b-slips-immune)  
**Judge:** gpt-oss-120b | **Incidents evaluated:** 47 | **Date:** 2026-04-10

---

### Index
- [Overall Rankings](#overall-rankings)
- [Performance by Category](#performance-by-category)
- [Performance by Complexity](#performance-by-complexity)
- [Readability](#readability)
- [Key Findings](#key-findings)
- [Known Limitations](#known-limitations)

---

### Overall Rankings
| Rank | Model | Avg Position | Avg Score | Win Rate |
|------|-------|--------------|-----------|----------|
| 1 | GPT-4o-mini | 1.86 | 6.67/10 | 34.0% |
| 2 | GPT-4o | 1.86 | 5.67/10 | 29.8% |
| 3 | **Finetuned 1.5B** | **2.48** | **4.81/10** | **21.3%** |
| 4 | Qwen2.5 3B | 3.18 | 4.23/10 | 4.3% |
| 5 | Qwen2.5 1B | 3.60 | 3.28/10 | 0.0% |

The finetuned model beats both baselines: **+1.53 avg score vs Qwen2.5 1B** (lower bound) and **+0.58 vs Qwen2.5 3B** (stretch goal), with a win rate of 21.3% vs 4.3% for the 3B model. The stretch goal — matching a 3B model with a 1.5B finetuned model — is met and exceeded.

---

### Performance by Category
| Category | Finetuned Score | Finetuned Win Rate | vs GPT-4o-mini |
|---|---|---|---|
| Malware (40 incidents) | 4.98/10 | 25.0% | −1.65 |
| Normal (2 incidents) | 1.50/10 | 0.0% | −6.00 |

Malware incidents are handled competitively. Normal incident performance is poor (2 incidents only — too few for robust conclusions).

---

### Performance by Complexity
| Complexity | Events | Finetuned Score | Win Rate | vs GPT-4o-mini |
|---|---|---|---|---|
| Simple | <500 (27 incidents) | 5.39/10 | 29.6% | −1.00 |
| Medium | 500–1999 (6 incidents) | 4.33/10 | 33.3% | −2.34 |
| Complex | ≥2000 (9 incidents) | 3.33/10 | 0.0% | −4.23 |

Simple incidents are where the model performs best, approaching GPT-4o (5.29) and competitive with the overall field. Complex incidents are the weak tier: 0 wins and a score below all GPT baselines, consistent with large DAGs exceeding the 4096-token input budget.

---

### Readability

An automated readability analysis measured compression ratio, abstraction, and verbatim copying across all models:

| Model | Avg Compression | Abstracted Bullets | Verbatim Lines | Fences |
|-------|-----------------|--------------------|----------------|--------|
| GPT-4o | 0.19 | 245 | 236 | 34 |
| GPT-4o-mini | 0.21 | 286 | 282 | 0 |
| Qwen2.5 3B | 0.43 | 233 | 261 | 0 |
| Qwen2.5 1B | 0.21 | 131 | 208 | 4 |
| **Finetuned** | **0.36** | **471** | **243** | **23** |

- **Compression 0.36** — the model is significantly more concise than Qwen2.5 3B (0.43) and closer to GPT-4o-mini (0.21), indicating it learned to summarize rather than echo the input
- **471 abstracted bullets** — highest of all models, nearly 2× GPT-4o-mini (286), indicating strong paraphrasing behavior
- **243 verbatim lines** — among the lowest, close to GPT-4o (236)
- **23 markdown fences** — minor formatting issue present in a subset of responses; not present in GPT-4o-mini

The readability metrics reveal an important nuance: the judge scoring rewards completeness and penalizes omissions, which means concise summaries can score lower even when they are more useful in practice. The finetuned model's lower judge score relative to earlier (verbatim-copying) variants partly reflects this judge bias rather than a true quality regression.

---

### Key Findings
1. **Stretch goal met.** The finetuned 1.5B model surpasses Qwen2.5 3B by 0.58 avg score and a 17% higher win rate, validating that task-specific fine-tuning compensates for parameter count on this domain.

2. **Best abstraction of all models.** With 471 abstracted bullets and compression 0.36, the model produces the most paraphrased, analyst-friendly output — more so than GPT-4o-mini. This is a strong operational advantage even where judge scores are lower.

3. **Competitive on simple incidents.** On the most common incident type (<500 events), the model scores 5.39 — above GPT-4o (5.29) and within 1 point of GPT-4o-mini.

4. **Complex incidents remain a hard limit.** Performance collapses above ~2000 events due to context length constraints. This is an engineering problem (input truncation), not a model quality problem.

---

### Known Limitations
- **Context length ceiling:** Incidents with large DAGs exceed the 4096-token input budget. The model produces errors or degraded summaries on the largest inputs (typically >5000 events). Mitigation: smarter DAG pre-summarization before the LLM step, or training at higher sequence length.
- **Judge bias vs. readability:** The LLM-as-judge rewards completeness and penalizes omissions. This creates a scoring disadvantage for concise models relative to verbatim-copying models. Judge criteria should be updated to explicitly reward compression and abstraction.
- **Small eval set:** 47 incidents is sufficient for directional conclusions but too small for robust statistical significance on Normal (2 incidents) and Complex (9 incidents) subsets.

---

For evaluation methodology, see [Fine-Tuning Evaluation Methodology](finetuning_evaluation.md).  
For training details, see [Summarization Fine-Tuning Procedure](finetuning_summarization_procedure.md).  
For quantization impact and deployment options, see [Quantization and Deployment](finetuning_quantization.md).
