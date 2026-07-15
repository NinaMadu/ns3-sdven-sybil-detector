"""
Gemma-2 has no `system` chat role — its chat template raises "System role not
supported". The stage-2 agent datasets (data_a{1,2,3}) carry the agent's ROLE
prompt in a leading system message, so they can't be fed to Gemma as-is.

This script produces Gemma-compatible copies (data_gemma2_2b_a{1,2,3}) by folding
the system message into the front of the first user turn — the standard Gemma
convention. NOTHING is dropped: the full agent-specialization text is preserved,
just carried under the user role. The original data_a* dirs (used by the Qwen and
Llama runs) are left completely untouched, so those results stay reproducible.

Usage:
    python prep_gemma_data.py            # rebuild all three gemma dirs
"""

import json
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
SUFFIX = "gemma2_2b"          # -> data_gemma2_2b_a{1,2,3}
SPLITS = ("train", "val", "test")


def fold_system(messages):
    """Return messages with any leading system turn merged into the first user turn."""
    if messages and messages[0]["role"] == "system":
        sys_txt = messages[0]["content"]
        rest = messages[1:]
        # first non-system turn is the user context; prepend the role prompt to it.
        for m in rest:
            if m["role"] == "user":
                m = dict(m)  # copy (defensive)
                m["content"] = sys_txt + "\n\n" + m["content"]
                # rebuild list with the modified user turn
                out, done = [], False
                for mm in rest:
                    if not done and mm["role"] == "user":
                        out.append(m); done = True
                    else:
                        out.append(mm)
                return out
        # no user turn (shouldn't happen) -> demote system to user
        return [{"role": "user", "content": sys_txt}] + rest
    return messages


def main():
    for agent in ("a1", "a2", "a3"):
        src = os.path.join(_HERE, f"data_{agent}")
        dst = os.path.join(_HERE, f"data_{SUFFIX}_{agent}")
        os.makedirs(dst, exist_ok=True)
        for split in SPLITS:
            sp = os.path.join(src, f"{split}.jsonl")
            if not os.path.exists(sp):
                continue
            n = 0
            with open(sp) as fin, open(os.path.join(dst, f"{split}.jsonl"), "w") as fout:
                for line in fin:
                    rec = json.loads(line)
                    rec["messages"] = fold_system(rec["messages"])
                    fout.write(json.dumps(rec) + "\n")
                    n += 1
            print(f"  {agent}/{split}: {n} rows -> {dst}/{split}.jsonl")
    print("done.")


if __name__ == "__main__":
    main()
