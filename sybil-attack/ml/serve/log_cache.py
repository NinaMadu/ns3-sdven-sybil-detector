"""
log_cache — incremental CSV tail reader for the real-time daemon.

The daemon scores the SAME growing log files on every SCORE. Re-reading/parsing a
multi-GB CSV per window is the perf blocker (~60 s/SCORE, dominated by the read, not
the LLM). A LogCache parses each log ONCE, then reads only the bytes APPENDED since the
last refresh (the sim writes in append mode), so per-SCORE cost drops to the new tail.

  cache = LogCache(path, usecols, time_col="time")
  cache.refresh()            # ingest appended rows (no-op if the file hasn't grown)
  rows = cache.upto(t)       # causal view: all cached rows with time_col <= t

`usecols` is a predicate (name -> bool) or list, applied on both the header read and the
header-less tail read (same column order). A partial final line (mid-write during a live
sim) is left un-consumed until its newline arrives. `nrows` caps the initial read for
tests on already-complete logs (then refresh is a no-op — no giant tail re-read).
"""

import io
import itertools
import os
import sys

import pandas as pd


class LogCache:
    def __init__(self, path, usecols, time_col="time", nrows=None):
        self.path = str(path)
        self.usecols = usecols
        self.time_col = time_col
        self.nrows = nrows
        self.df = None
        self.offset = 0
        self._cols = None
        self.dropped = 0            # count of malformed rows dropped (torn live writes)

    def _header(self):
        with open(self.path) as f:
            return f.readline().rstrip("\n").split(",")

    def _parse_valid(self, text, has_header):
        """Parse CSV `text`, keeping ONLY rows whose field count matches the header.

        The sim writes some log rows NON-ATOMICALLY (two independent append streams to
        the same file interleave), producing TORN lines: a logical row split across two
        physical lines, or two rows merged. Both fragments have the WRONG number of
        fields (verified: 877k good 11-field rows vs ~180 torn rows scattered across
        1..21 fields). Field-count filtering is column-agnostic and catches ALL of them,
        unlike checking any single column (a torn fragment can leave a valid-looking
        value in one column while shifting a float into an int column -> astype crash).
        Returns a DataFrame (usecols-selected, time coerced numeric) or None if empty.
        """
        ncol = len(self._cols)
        lines = text.splitlines(keepends=True)
        data = lines[1:] if has_header else lines
        good, dropped = [], 0
        for ln in data:
            if ln.count(",") + 1 == ncol:
                good.append(ln)
            elif ln.strip():
                dropped += 1
        if dropped:
            self.dropped += dropped
            print(f"[LogCache] {os.path.basename(self.path)}: dropped {dropped} malformed "
                  f"(wrong field count) row(s)", file=sys.stderr, flush=True)
        if not good:
            return None
        hdr = ",".join(self._cols) + "\n"
        df = pd.read_csv(io.StringIO(hdr + "".join(good)), usecols=self.usecols,
                         low_memory=False)
        df[self.time_col] = pd.to_numeric(df[self.time_col], errors="coerce")
        return df[df[self.time_col].notna()]

    def refresh(self):
        """Ingest rows appended since the last refresh (or do the initial full read)."""
        if not os.path.exists(self.path):
            return
        size = os.path.getsize(self.path)
        if self.df is None:                          # initial read
            self._cols = self._header()
            with open(self.path) as f:
                text = ("".join(itertools.islice(f, self.nrows + 1))
                        if self.nrows else f.read())
            self.df = self._parse_valid(text, has_header=True)
            if self.df is None:
                self.df = pd.DataFrame()
            # mark the whole current file consumed: a capped test read must NOT then
            # re-ingest the (huge) remainder; a live sim grows past this offset.
            self.offset = size
            return
        if self.nrows is not None or size <= self.offset:
            return                                   # capped (test) or nothing new
        with open(self.path, "rb") as fh:
            fh.seek(self.offset)
            data = fh.read(size - self.offset)
        nl = data.rfind(b"\n")                       # drop a partial trailing line
        if nl < 0:
            return
        chunk = data[:nl + 1].decode("utf-8", "replace")
        new = self._parse_valid(chunk, has_header=False)
        if new is not None and len(new):
            self.df = pd.concat([self.df, new], ignore_index=True)
        self.offset += nl + 1

    def upto(self, t):
        """Causal view: rows with time_col <= t (all rows if t is None)."""
        if self.df is None or len(self.df) == 0:
            return pd.DataFrame()
        if t is None:
            return self.df
        return self.df[self.df[self.time_col] <= float(t)]

    def between(self, t0, t1):
        """Rows with t0 <= time_col <= t1. Used for bounded incremental windowing:
        with only_new the daemon only needs windows just before/after last_t, so it
        windows a recent slice instead of all history (t0 = -inf reproduces upto)."""
        if self.df is None or len(self.df) == 0:
            return pd.DataFrame()
        tc = self.df[self.time_col]
        m = tc <= float(t1)
        if t0 is not None and t0 != float("-inf"):
            m &= tc >= float(t0)
        return self.df[m]
