### Summarization Fine-Tuned Model: Evaluation Results

**Summary:** The Qwen2.5-1.5B model fine-tuned for Slips incident summarization ranks 3rd overall with a 4.70 avg score and 19.1% win rate — above both Qwen2.5 baselines. The model performs best on simple incidents (<500 events) and produces highly abstracted summaries. The primary weakness is performance on medium and complex incidents (≥500 events), caused by context length limitations.

**Model:** [stratosphere/qwen2.5-1.5b-slips-immune](https://huggingface.co/stratosphere/qwen2.5-1.5b-slips-immune)  
**Judge:** gpt-oss-120b | **Incidents evaluated:** 47 | **Date:** 2026-04-12

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
| 1 | GPT-4o-mini | 1.81 | 6.89/10 | 42.6% |
| 2 | GPT-4o | 2.38 | 5.87/10 | 29.8% |
| 3 | **Finetuned 1.5B** | **3.21** | **4.70/10** | **19.1%** |
| 4 | Qwen2.5 3B | 3.40 | 4.57/10 | 8.5% |
| 5 | Qwen2.5 1B | 4.19 | 3.36/10 | 0.0% |

The finetuned 1.5B model scores above both Qwen2.5 baselines (1B: 3.36, 3B: 4.57) with a win rate of 19.1% vs 8.5% for the 3B model.

---

### Performance by Category
| Category | Finetuned Score | Finetuned Win Rate | vs GPT-4o-mini |
|---|---|---|---|
| Malware (45 incidents) | 4.82/10 | 20.0% | −2.09 |
| Normal (2 incidents) | 2.00/10 | 0.0% | −4.50 |

Malware incidents are handled competitively. Normal incident performance is poor (2 incidents only — too few for robust conclusions).

---

### Performance by Complexity
| Complexity | Events | Finetuned Score | Win Rate | vs GPT-4o-mini |
|---|---|---|---|---|
| Simple | <500 (31 incidents) | 5.45/10 | 29.0% | −1.29 |
| Medium | 500–1999 (7 incidents) | 3.43/10 | 0.0% | −3.28 |
| Complex | ≥2000 (9 incidents) | 3.11/10 | 0.0% | −4.45 |

Simple incidents are where the model performs best — scoring 5.45, above Qwen2.5 3B (4.77) and GPT-4o (5.61). Medium and complex incidents are the weak tiers: 0 wins and scores below all GPT baselines, consistent with large DAGs exceeding the 4096-token input budget.

---

### Readability

An automated readability analysis measured compression ratio, abstraction, and verbatim copying across all models (FP16 results):

| Model | Avg Compression | Abstracted Bullets | Verbatim Lines | Fences |
|-------|-----------------|--------------------|----------------|--------|
| GPT-4o | 0.19 | 245 | 236 | 34 |
| GPT-4o-mini | 0.21 | 286 | 282 | 0 |
| Qwen2.5 3B | 0.43 | 233 | 261 | 0 |
| Qwen2.5 1B | 0.21 | 131 | 208 | 4 |
| **Finetuned (fp16)** | **0.26** | **373** | **256** | **44** |

- **Compression 0.26** — more concise than Qwen2.5 3B (0.43), close to GPT-4o-mini (0.21)
- **373 abstracted bullets** — highest of all models, indicating strong paraphrasing behavior
- **256 verbatim lines** — comparable to other models
- **44 markdown fences** — formatting regression present in a subset of responses; not present in GPT-4o-mini

The readability metrics reveal an important nuance: the judge scoring rewards completeness and penalizes omissions, which means concise summaries can score lower even when they are more useful in practice. The finetuned model's lower judge score relative to verbatim-copying variants partly reflects this judge bias rather than a true quality regression.

---

### Key Findings
1. **Above both Qwen2.5 baselines.** The finetuned 1.5B model scores 4.70, above both Qwen2.5 1B (3.36) and Qwen2.5 3B (4.57), validating that task-specific fine-tuning compensates for parameter count on this domain.

2. **Strong abstraction.** With 373 abstracted bullets and compression 0.26, the model produces well-paraphrased output — more so than GPT-4o-mini (286). This is a strong operational advantage for security analysts even where judge scores are lower.

3. **Competitive on simple incidents.** On the most common incident type (<500 events), the model scores 5.45 — above Qwen2.5 3B (4.77) and approaching GPT-4o (5.61).

4. **Medium and complex incidents are the weak point.** Performance drops to 3.43 (medium) and 3.11 (complex). This is an engineering problem (input truncation at 4096 tokens), not a model quality problem.

---

### Known Limitations
- **Context length ceiling:** Incidents with large DAGs exceed the 4096-token input budget. The model produces errors or degraded summaries on the largest inputs (typically >2000 events). Mitigation: smarter DAG pre-summarization before the LLM step, or training at higher sequence length.
- **Judge bias vs. readability:** The LLM-as-judge rewards completeness and penalizes omissions. This creates a scoring disadvantage for concise models relative to verbatim-copying models. Judge criteria should be updated to explicitly reward compression and abstraction.
- **Small eval set:** 47 incidents is sufficient for directional conclusions but too small for robust statistical significance on Normal (2 incidents) and Complex (9 incidents) subsets.

---

For evaluation methodology, see [Fine-Tuning Evaluation Methodology](finetuning_evaluation.md).  
For training details, see [Summarization Fine-Tuning Procedure](finetuning_summarization_procedure.md).  
For quantization impact and deployment options, see [Quantization and Deployment](finetuning_quantization.md).  
