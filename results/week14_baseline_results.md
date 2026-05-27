# Week 14 Baseline Results

Owner: Fan Sheng-Wei  
Branch: `data`  
Date: 2026-05-27

## Scope

This Week 14 result file records the baseline data and evaluation artifacts required by `docs/spec.md`. The goal is to prepare a clean seed dataset, an initial prompt-injection attack set, and validation scripts that can be used in later n8n and LLM evaluation.

## Implemented Artifacts

- `data/raw/normal_emails.csv`
- `data/raw/spam_emails.csv`
- `data/raw/malicious_emails.csv`
- `data/processed/email_eval_set.jsonl`
- `data/attacks/prompt_injection_cases.jsonl`
- `data/attacks/struqlite_attack_set.jsonl`
- `src/evaluation/build_attack_set.py`
- `src/evaluation/run_eval.py`
- `src/evaluation/metrics.py`
- `tests/test_eval_metrics.py`
- `scripts/run_local_eval.sh`
- `scripts/demo_seed_data.sh`

## Local Validation

Command:

```bash
./scripts/run_local_eval.sh
```

Output:

```text
# Week 14 Baseline Data/Evaluation Summary

Raw CSV seed emails: 36
Evaluation seed emails: 36
Prompt-injection attack cases: 10
Total records prepared: 46

Raw CSV label distribution:
  - malicious : 12
  - normal    : 12
  - trash     : 12

Evaluation label distribution:
  - malicious : 12
  - normal    : 12
  - trash     : 12

Attack expected-label distribution:
  - malicious : 8
  - normal    : 1
  - trash     : 1

Attack type distribution:
  - base64_instruction         : 1
  - benign_with_injection_text : 1
  - control_characters         : 1
  - delimiter_spoofing         : 1
  - fake_json_completion       : 1
  - fake_n8n_command           : 1
  - fake_system_message        : 1
  - ignore_instruction         : 1
  - multilingual_chinese       : 1
  - schema_change_request      : 1

Source type distribution:
  - synthetic_attack_seed : 10
  - synthetic_seed        : 36

Validation checks:
  - raw CSV files are readable
  - required webhook fields present
  - expected_label is one of normal/trash/malicious
  - urls and attachment_names are JSON arrays
  - message_id values are non-empty and unique within each file

Validation status: passed
```

## Unit Tests

Command:

```bash
python3 -m unittest discover -s tests
```

The tests cover basic evaluation metrics that will be used after n8n and LLM predictions are collected.

Output:

```text
....
----------------------------------------------------------------------
Ran 4 tests in 0.000s

OK
```

## Week 15 Next Step

The next data-track step is to run `data/processed/email_eval_set.jsonl` and `data/attacks/struqlite_attack_set.jsonl` through the n8n webhook, save model predictions, and calculate accuracy, malicious recall, normal false positive rate, manual review rate, and attack success rate.

The expected prediction record fields for Week 15 are:

- `message_id`
- `expected_label`
- `predicted_label` or `label`
- `confidence`
- `final_action`
- `validation_status`

The metric helpers in `src/evaluation/metrics.py` already accept these fields, so Week 15 can focus on collecting n8n/LLM outputs and writing them into a result file.
