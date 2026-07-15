"""
Gemma-2 wrapper around consensus_eval.py.

Gemma's tokenizer has no `system` role, so the eval must read the Gemma-folded
splits (data_gemma2_2b_a{1,2,3}) instead of the system-carrying originals. This
wrapper monkeypatches consensus_eval.load_split to point at those dirs and then
delegates to the unmodified consensus_eval.main(). All scoring, consensus (Eq
3.22) and output logic is reused verbatim — nothing in consensus_eval.py is
edited, so the Qwen and Llama runs are unaffected.

All CLI args are forwarded straight to consensus_eval.main() (--base, --adapters,
--scorecards, --preds, ...).
"""

import json
import os

import consensus_eval as CE

_HERE = os.path.dirname(os.path.abspath(__file__))
SUFFIX = "gemma2_2b"


def _load_split_gemma(agent, split):
    path = os.path.join(_HERE, f"data_{SUFFIX}_{agent}", f"{split}.jsonl")
    return [json.loads(l) for l in open(path)]


if __name__ == "__main__":
    CE.load_split = _load_split_gemma      # redirect to gemma-folded data
    CE.main()
