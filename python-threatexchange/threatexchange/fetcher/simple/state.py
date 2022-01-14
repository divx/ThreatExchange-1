# Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved


from collections import defaultdict
from dataclasses import dataclass
import typing as t

from threatexchange.signal_type.signal_base import SignalType
from threatexchange.fetcher import fetch_state


@dataclass
class TypedSignalWithOpinion:
    signal_type: SignalType
    signal: str
    opinion: fetch_state.SignalOpinion


class SimpleFetchDelta(fetch_state.FetchDeltaBase):
    """A simpler merger based on type and owner"""

    def __init__(
        self,
        records: t.List[TypedSignalWithOpinion],
        checkpoint: fetch_state.TFetchStateCheckpoint,
    ) -> None:
        self.opinions = defaultdict(dict)
        self.checkpoint = checkpoint
        for record in records:
            self._merge_one(record.signal_type, record.signal_type, record.opinion)

    def record_count(self) -> int:
        return len(self.signals_to_opinions)  # Lie, saves merge_one counter

    def merge(self, subsequent: "SimpleFetchDelta") -> None:
        for k, v in subsequent.opinions.items():
            self.opinions[k].update(v)

    def _merge_one(
        self, signal_type: SignalType, signal: str, opinion: fetch_state.SignalOpinion
    ) -> None:
        self.opinions[signal_type, signal][opinion.owner] = opinion

    def next_checkpoint(self) -> fetch_state.TFetchStateCheckpoint:
        return self.checkpoint
