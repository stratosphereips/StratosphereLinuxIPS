### Fine-Tuning Frameworks for GGUF Deployment on Raspberry Pi 5

**Keywords:** Local Inference, GGUF Format, Raspberry Pi 5

**TL;DR:** Among the evaluated frameworks, Unsloth stands out as the best fit due to its integrated GGUF export capabilities, minimal workflow complexity, and hardware-optimized quantization support, aligning perfectly with the IMMUNE project's goals and the Raspberry Pi 5’s limitations.


### Index

- [Fine-Tuning Frameworks for GGUF Deployment on Raspberry Pi 5](#fine-tuning-frameworks-for-gguf-deployment-on-raspberry-pi-5)
- [Evaluation Criteria](#evaluation-criteria)
- [Framework Analysis](#framework-analysis)
  - [Unsloth](#unsloth-httpsgithubcomunslothaiunsloth)
  - [Axolotl](#axolotl-httpsgithubcomopenaccess-ai-collectiveaxolotl)
  - [TorchTune](#torchtune-httpsgithubcompytorchtune)
  - [LlamaFactory and LMTuner](#llamafactory-httpsgithubcomhiyougallama-factory-and-lmtuner-httpsgithubcomoptimalscalelmflow)
  - [Transformers + PEFT](#transformers--peft-httpsgithubcomhuggingfacepeft)
- [Comparison Table](#comparison-table)
- [Recommended Workflow](#recommended-workflow)
- [Conclusion](#conclusion)


### Summary

The IMMUNE project aims to enable efficient local inference of large language models on resource-constrained devices such as the Raspberry Pi 5. Given the limited computational power, absence of dedicated GPUs, and restricted memory capacity of the RPI5, there is a need for optimizing models for CPU-only deployment. This document specifically targets identifying and analyzing fine-tuning frameworks that facilitate creating models compatible with the GGUF format, optimized for inference using runtimes like llama.cpp and Ollama which are inference engines considered for this project. Given these constraints, parameter-efficient fine-tuning methods such as LoRA and QLoRA are prioritized to minimize resource demands during training and enable smooth deployment. The fine-tuning itself will be performed off-device on more capable hardware, followed by conversion to GGUF with quantization to reduce memory footprint and latency during inference on the RPI5. 


#### Evaluation Criteria

When selecting a fine-tuning framework for our project, several key constraints and goals must be considered to ensure efficient and practical deployment on the Raspberry Pi 5:

1. **Support for Parameter-Efficient Fine-Tuning Methods**  
   The framework should support techniques like LoRA or QLoRA, which significantly reduce resource consumption during fine-tuning by adapting only a small subset of model parameters. This is crucial for minimizing the training time and hardware requirements.

2. **Compatibility with GGUF Export**  
   Direct or seamless exporting to the GGUF format is essential. GGUF allows optimized CPU-friendly inference on devices like the Raspberry Pi 5. Frameworks that lack integrated GGUF export add complexity via additional conversion steps, making deployment more cumbersome.

3. **Integration with Hugging Face Ecosystem**  
   Given the wide availability of pre-trained models in Hugging Face format, it is advantageous if the framework supports Hugging Face models natively. This ensures access to a broad range of architectures and simplifies model loading and fine-tuning pipelines.

4. **Workflow and Tooling Complexity**  
   The complexity of setup, training workflow, and required tooling impacts reproducibility and ease of deployment. Frameworks minimizing dependencies and intermediate manual steps are preferred, especially when the priority is a streamlined deployment pipeline rather than extensive experimentation.

By carefully evaluating frameworks against these criteria, one can select the most suitable fine-tuning tool for producing GGUF-compatible, quantized models optimized for resource-constrained CPU environments.


#### Framework Analysis

**Unsloth (**[**https://github.com/unslothai/unsloth**](https://github.com/unslothai/unsloth)**)**

Unsloth is currently the most efficient and straightforward framework for this task. It supports fast, memory-efficient fine-tuning using LoRA, and includes built-in support for exporting fine-tuned models directly to GGUF format. This eliminates the need for manual adapter merging or external scripts. The model can be quantized during export using GGUF-compatible formats such as `q4_k_m`, which are optimized for CPU inference. For a deployment target like Raspberry Pi, where low memory footprint and fast loading are essential, Unsloth provides the most streamlined workflow. Its ease of use, minimal dependencies, and direct compatibility with llama.cpp make it a strong candidate.

**Axolotl (**[**https://github.com/OpenAccess-AI-Collective/axolotl**](https://github.com/OpenAccess-AI-Collective/axolotl)**)**

Axolotl is a flexible and scalable fine-tuning framework often used in distributed or multi-GPU environments. It supports a variety of training configurations, including DeepSpeed and FSDP. However, it does not natively export to GGUF. Instead, fine-tuned models must be saved in Hugging Face format and later converted using the `convert.py` utility from llama.cpp. While Axolotl is more powerful for large-scale training, it introduces additional steps that may be unnecessary for this project's goals.

**TorchTune (**[**https://github.com/pytorch/tune**](https://github.com/pytorch/tune)**)**

TorchTune, developed by the PyTorch team, is a modular and extensible framework designed for research and experimentation. It integrates with PyTorch-native tools and supports LoRA-based fine-tuning. Like Axolotl, TorchTune outputs models in standard Hugging Face format, requiring manual conversion to GGUF post-training. TorchTune is still evolving, and while it is well-suited for experimentation and custom pipelines, it is not optimized for deployment-focused workflows like the one required here.

**LlamaFactory (**[**https://github.com/hiyouga/LLaMA-Factory**](https://github.com/hiyouga/LLaMA-Factory)**)** and **LMTuner (**[**https://github.com/OptimalScale/LMFlow**](https://github.com/OptimalScale/LMFlow)**)**

Other frameworks such as LlamaFactory and LMTuner offer UI-based or scripting interfaces for managing fine-tuning jobs. They support efficient tuning methods and cover a wide range of models. However, like Axolotl and TorchTune, they require additional steps to convert models to GGUF. These frameworks are better suited for research and experimentation rather than minimal-dependency deployment pipelines.

**Transformers + PEFT (**[**https://github.com/huggingface/peft**](https://github.com/huggingface/peft)**)**

Finally, using Transformers with PEFT directly offers the highest level of control and customizability but demands manual orchestration of adapter training, merging, and post-processing. While technically viable, this approach increases implementation complexity and is not ideal for deployment pipelines that must remain simple and reproducible.

The summary table below highlights the key differences and strengths of each framework evaluated for GGUF-compatible fine-tuning on Raspberry Pi 5.

#### Comparison Table

| Framework           | LoRA Support | GGUF Export        | Workflow Complexity | Direct GGUF Deployment Ready | URL                                                                                                        |
| ------------------- | ------------ | ------------------ | ------------------- | ---------------------------- | ---------------------------------------------------------------------------------------------------------- |
| Unsloth             | Yes          | Yes                | Low                 | Yes                          | [https://github.com/unslothai/unsloth](https://github.com/unslothai/unsloth)                               |
| Axolotl             | Yes          | No (via llama.cpp) | Medium              | Partially                    | [https://github.com/OpenAccess-AI-Collective/axolotl](https://github.com/OpenAccess-AI-Collective/axolotl) |
| TorchTune           | Yes          | No (via llama.cpp) | Medium              | No                           | [https://github.com/pytorch/tune](https://github.com/pytorch/tune)                                         |
| LlamaFactory        | Yes          | No (via llama.cpp) | Medium              | No                           | [https://github.com/hiyouga/LLaMA-Factory](https://github.com/hiyouga/LLaMA-Factory)                       |
| LMTuner             | Yes          | No (via llama.cpp) | Medium              | No                           | [https://github.com/OptimalScale/LMFlow](https://github.com/OptimalScale/LMFlow)                           |
| Transformers + PEFT | Yes          | No (via llama.cpp) | High                | No                           | [https://github.com/huggingface/peft](https://github.com/huggingface/peft)                                 |

#### Recommended Workflow

The recommended approach is to fine-tune the model using Unsloth, leveraging its native support for LoRA and integrated GGUF export. Unsloth is designed for extreme efficiency: it enables fine-tuning of models such as LLaMA, Mistral and the Qwen using significantly less GPU memory than traditional methods. It supports both 8-bit and 4-bit quantized training, and is optimized for speed and hardware compatibility. Unsloth offers high throughput, supports full compatibility with Hugging Face models, and includes methods for direct export to GGUF.

A basic usage example is as follows:

```python
from unsloth import FastLanguageModel
from transformers import TrainingArguments

# Load base model
model, tokenizer = FastLanguageModel.from_pretrained(
    model_name="unsloth/Qwen2.5-1.5B-Instruct",
    load_in_4bit=True,
    device_map="auto"
)

# Prepare the model for training with LoRA
model = FastLanguageModel.get_peft_model(
    model,
    r=8,
    lora_alpha=16,
    lora_dropout=0.05,
    bias="none",
    task_type="CAUSAL_LM"
)

# TrainingArguments as required by Hugging Face Trainer
args = TrainingArguments(
    output_dir="finetuned-model",
    per_device_train_batch_size=2,
    num_train_epochs=1,
    logging_steps=10,
    save_steps=500,
    learning_rate=2e-4
)

# Train the model with your data using Hugging Face Trainer (not shown)

# Save the trained model as GGUF
model.save_pretrained_gguf("finetuned_model", tokenizer, quantization_method="q4_k_m")
```

This process results in a quantized GGUF model that can be directly deployed for CPU inference on the Raspberry Pi using llama.cpp or compatible runtimes. This allows fine-tuning to be performed off-device using standard GPU hardware, followed by a one-step export process that produces a quantized GGUF model. The resulting model can be directly deployed to the Raspberry Pi and executed using llama.cpp or compatible runtime.

The exported GGUF model can be optimized using quantization schemes like `q4_k_m` or `q8_0`, depending on memory availability and performance needs. These formats balance model size and inference speed, making them suitable for constrained devices like the RPI5.

The complete set of scripts used for finetuning the used inside SLIPS Immune are avaiable 
[here](https://github.com/stratosphereips/Slips-tools/tree/main/unsloth-scripts)

not for mac. Currently, Unsloth does not support Apple Silicon processors, which means users with Mac devices using Apple Silicon (such as M1 or M2 chips) may face compatibility issues or be unable to use the framework effectively at this time.

#### Conclusion

For a deployment-focused workflow targeting CPU-only inference on the Raspberry Pi 5, Unsloth is the most efficient and practical fine-tuning framework. It reduces setup complexity, supports all necessary optimization steps, and directly outputs a model in the required GGUF format. Other frameworks like Axolotl or TorchTune are viable for more complex or large-scale setups but introduce additional post-processing steps that are unnecessary for this specific use case.

####
