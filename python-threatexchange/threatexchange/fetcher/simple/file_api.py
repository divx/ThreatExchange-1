# Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved

"""
The fetcher is the component that talks to external APIs to get and put signals

@see SignalExchangeAPI
"""


from dataclasses import dataclass
from pathlib import Path

from threatexchange.signal_type.pdq import PdqSignal
from threatexchange.fetcher import fetch_state as state
from threatexchange.fetcher.collab_config import CollaborationConfigBase
from threatexchange.fetcher.simple.state import (
    SimpleFetchDeltaWithSyntheticID,
)


@dataclass
class FileCollaborationConfig(CollaborationConfigBase):
    filename: str
    signal_type: str


class LocalFileSignalExchangeAPI:
    """
    Read simple signal files off the local disk.
    """

    def fetch_once(
        self, collab: FileCollaborationConfig, _checkpoint: state.FetchCheckpointBase
    ) -> state.FetchDeltaBase:
        """Fetch the whole file"""
        path = Path(collab.filename)
        assert path.exists(), f"No such file {path}"
        assert path.is_file(), f"{path} is not a file (is it a dir?)"

        # TODO - Support things other than just one item per line
        with path.open("r") as f:
            lines = f.readlines()

        return SimpleFetchDeltaWithSyntheticID.from_simple_opinons(
            PdqSignal, (line.trim() for line in lines)
        )
