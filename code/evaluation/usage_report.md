# Model and token usage report

## Full-dataset run

The final run processed all 518 requests and wrote the repository-root
`output.csv`. The agent makes no external LLM/API calls.

| Provider / runtime | Model | Calls | Input tokens | Output tokens | Estimated cost |
| --- | --- | ---: | ---: | ---: | ---: |
| None | No generative model used | 0 | 0 | 0 | $0.00 |
| RapidOCR / ONNX Runtime (local) | PP-OCRv4 detector, PP-OCRv4 recognizer, PP-OCR mobile v2.0 classifier | 11 image inferences | N/A | N/A | $0.00 |

The local OCR runtime processed the 11 participant-provided screenshot files.
OCR consumes image pixels and returns recognized text, so LLM token counts and
provider/API charges do not apply. No API keys, credentials, or external
personal-data processing were used.

| Total | Input tokens | Output tokens | Total tokens | Average tokens per request | Estimated total cost | Estimated cost per request |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Full dataset (518 requests) | 0 | 0 | 0 | 0 | $0.00 | $0.00 |
