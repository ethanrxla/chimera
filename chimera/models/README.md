# Models

## StarCoder artifacts
- Preserved path: D:\whitehat\models\starcoder\starcoder-code-stage1
- This artifact is not wired into Chimera yet.

## Loading later (high level)
- Use `transformers.AutoTokenizer.from_pretrained` and `AutoModelForCausalLM.from_pretrained` pointing at the model directory.
- Expect large disk and RAM requirements; consider Git LFS or external storage.

## Licensing/size notes
- Review the original StarCoder license and model card before redistribution.
- The size is large; keep it out of Docker images by default.
