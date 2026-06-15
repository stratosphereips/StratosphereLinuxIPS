# Slips Immune

This is the main guide to the documentation related to the changes done to Slips as part of incorporating the immunology ideas

### Architecture

- [Main Architecture of Slips Immune](https://stratospherelinuxips.readthedocs.io/en/develop/immune/immune_architecture.html)
- [Immunology-inspired Model for Slips](https://stratospherelinuxips.readthedocs.io/en/develop/immune/immunology_model.html)

###  RPI performance
- [Research RPI Limitations](https://stratospherelinuxips.readthedocs.io/en/develop/immune/research_rpi_limitations_and_define_acceptable_performance_benchmarks.html)
- [Slips Compatibility In The RPI](https://stratospherelinuxips.readthedocs.io/en/develop/immune/reimplement_slips_features_incompatible_with_the_rpi.html)
- [Installing Slips On the RPI](https://stratospherelinuxips.readthedocs.io/en/develop/immune/installing_slips_in_the_rpi.html)
- [Performance Evaluation](https://stratospherelinuxips.readthedocs.io/en/develop/immune/performance_evaluation.html)
- [Testing](https://stratospherelinuxips.readthedocs.io/en/develop/immune/testing.html)
- [LLM Research and Selection](https://stratospherelinuxips.readthedocs.io/en/develop/immune/research_and_selection_of_llm_candidates.html)
- [LLM RPI Performance](https://stratospherelinuxips.readthedocs.io/en/develop/immune/research_rpi_llm_performance.html)
- [Stress Testing](https://stratospherelinuxips.readthedocs.io/en/develop/immune/stress_testing.html)

### Updating Slips
- [Updating Slips](https://stratospherelinuxips.readthedocs.io/en/develop/immune/auto_update.html)


### Security & Network Configuration

- [ARP Poisoning](https://stratospherelinuxips.readthedocs.io/en/develop/immune/arp_poisoning.html)
- [ARP Poisoning Risks](https://stratospherelinuxips.readthedocs.io/en/develop/immune/arp_poisoning_risks.html)
- [Blocking with Slips as an Access Point](https://stratospherelinuxips.readthedocs.io/en/develop/immune/blocking_in_slips.html)
- [IDS-in-the-middle Traffic routing](https://stratospherelinuxips.readthedocs.io/en/develop/immune/ids_in_the_middle_traffic_routing.html)
- [RPI Failover Mechanisms](https://stratospherelinuxips.readthedocs.io/en/develop/immune/failover_mechanisms.html)
- [Security Audit](https://stratospherelinuxips.readthedocs.io/en/develop/immune/security_audit.html)

### Datasets & LLM Training

**Report Documents:**

- [Summarization Dataset Report](https://stratospherelinuxips.readthedocs.io/en/develop/immune/DATASET_REPORT.html) - Event summarization and behavior analysis
- [Risk Analysis Dataset Report](https://stratospherelinuxips.readthedocs.io/en/develop/immune/DATASET_RISK_REPORT.html) - Root cause and risk assessment

**Workflow Guides:**
- [Summarization Workflow Implementation](https://stratospherelinuxips.readthedocs.io/en/develop/immune/README_dataset_summary_workflow.html) - Step-by-step guide for generating summarization datasets
- [Risk Analysis Workflow Implementation](https://stratospherelinuxips.readthedocs.io/en/develop/immune/README_dataset_risk_workflow.html) - Step-by-step guide for generating risk datasets
- [Alert DAG Parser Documentation](https://stratospherelinuxips.readthedocs.io/en/develop/immune/README_alert_dag.html) - DAG structural analysis reference

**Datasets Evaluation (LLM-as-a-judge):**
- [LLM Evaluation Guide](https://stratospherelinuxips.readthedocs.io/en/develop/immune/LLM_EVALUATION_GUIDE.html) - How to evaluate and compare LLM models
- [LLM-as-Judge Rubric](https://stratospherelinuxips.readthedocs.io/en/develop/immune/LLM_JUDGE_RUBRIC.html) - Scoring criteria for cause analysis and risk assessment evaluation (two-stage rubric, max 60 pts)
- [Summarization Dataset Evaluation Results](https://harpomaxx.github.io/gh-web-host/slips-immune-llm-results/summary_dashboard.html) - Performance metrics for summarization models.
- [Risk Analysis Dataset Evaluation Results](https://harpomaxx.github.io/gh-web-host/slips-immune-llm-results/risk_dashboard.html) - Performance metrics for risk assessment models

**LLM finetuning**
- [LLM RPI Finetuning Frameworks](https://stratospherelinuxips.readthedocs.io/en/develop/immune/finetuning_frameworks_rpi_5.html) - Framework selection rationale (Unsloth vs alternatives)
- [Fine-Tuning Approach](https://stratospherelinuxips.readthedocs.io/en/develop/immune/finetuning_procedure.html) - General pipeline: LoRA, GGUF export, hardware setup
- [Fine-Tuning Evaluation Methodology](https://stratospherelinuxips.readthedocs.io/en/develop/immune/finetuning_evaluation.html) - LLM-as-judge pipeline, metrics, and breakdown dimensions
- [Quantization and Deployment](https://stratospherelinuxips.readthedocs.io/en/develop/immune/finetuning_quantization.html) - GGUF conversion, Ollama publication, and quantization performance analysis

  *Incident Summarization task:*
  - [Summarization Training Procedure](https://stratospherelinuxips.readthedocs.io/en/develop/immune/finetuning_summarization_procedure.html) - Dataset filtering, ground truth selection, system prompt
  - [Summarization Fine-Tuned Model: Evaluation Results](https://stratospherelinuxips.readthedocs.io/en/develop/immune/finetuning_results.html) - Benchmark results for the finetuned Qwen2.5-1.5B

  *Risk Assessment & Cause Analysis task:*
  - [Risk Assessment Training Procedure](https://stratospherelinuxips.readthedocs.io/en/develop/immune/finetuning_risk_procedure.html) - Dataset filtering, best-of-N selection, combined adapter training
  - [Risk Fine-Tuned Model: Evaluation Results](https://stratospherelinuxips.readthedocs.io/en/develop/immune/finetuning_risk_results.html) - Benchmark results for the finetuned Qwen2.5-1.5B risk model

  *Unified model (Summary + Cause + Risk):*
  - [Unified Training Procedure](https://stratospherelinuxips.readthedocs.io/en/develop/immune/finetuning_unified_procedure.html) - Single adapter for all three tasks: dataset merging, lora_r=128 + RSLoRA, version history
  - [Unified Fine-Tuned Model: Evaluation Results](https://stratospherelinuxips.readthedocs.io/en/develop/immune/finetuning_unified_results.html) - Benchmark results vs standalone models and quantization impact
