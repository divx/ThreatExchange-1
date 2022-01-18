# Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved

"""
Base classes for passing data between SignalExchangeAPIs and other interfaces.

Many implementations will choose to extend these to add additional metadata
needed to power API features.
"""


from dataclasses import dataclass
from enum import Enum
import typing as t

from threatexchange.signal_type.signal_base import SignalType


@dataclass
class FetchCheckpointBase:
    """
    If you need to store checkpoint information, this is the place to do it
    """


class SignalOpinionCategory(Enum):
    """
    What the opinion on a signal is.

    Some APIs may not support all of these, but each of these should influence
    what action you might take as a result of matching, otherwise it might
    make more sense as a tag
    """

    FALSE_POSITIVE = 0  # Signal generates false positives
    WORTH_INVESTIGATING = 1  # Indirect indicator
    TRUE_POSITIVE = 2  # Confirmed meets category


@dataclass
class SignalOpinion:
    """
    The metadata of a single signal upload.

    Certain APIs won't have any concept of owner, category, or tags,
    in which case owner=0, category=TRUE_POSITIVE, tags=[] is reasonable
    default.

    Some implementations may extend this to store additional API-specific data

    @see threatexchange.fetch_api.SignalExchangeAPI
    """

    owner: int
    category: SignalOpinionCategory
    tags: t.List[str]


@dataclass
class FetchedSignalDataBase:
    """
    Metadata to make decisions on matches and power feedback on the fetch API.

    You likely need to extend this for your API to include enough context for
    SignalExchangeAPI.report_seen() and others.

    If your API supports multiple databases or collections, you likely
    will need to store that here.
    """

    opinions: t.List[SignalOpinion]
    metadata_id: int = 0  # If your API doesn't support IDs, leave this as 0

    def merge(self, newer: "FetchedStateBase") -> None:
        """
        Merge with another state object. This object is always the older state

        The usual reaon this happens is the stored state is being combined
        with the fetched state. Some APIs might append, while others might
        replace.
        """
        raise NotImplementedError


class FetchDeltaBase:
    """
    Contains the result of a fetch.

    You'll need to extend this, but it only to be interpretable by your
    API's version of FetchedState
    """

    def record_count(self) -> int:
        """Helper for --limit"""
        return 1

    def next_checkpoint(self) -> FetchCheckpointBase:
        """A serializable checkpoint for fetch."""
        raise NotImplementedError


# TODO t.Generic[TFetchDeltaBase, TFetchedSignalDataBase, FetchCheckpointBase]
#      to help keep track of the expected subclasses for an impl
class FetchedStateBase:
    """
    An interface to previously fetched or persisted state.

    You will need to extend this for your API, but even worse, there
    might need to be multiple versions for a single API if it's being
    used by Hasher-Matcher-Actioner, since that might want to specialcase
    for AWS components.

    = A Note on Metadata ID =
    It's assumed that the storage will be split into a scheme that allows
    addressing individual IDs. Depending on the implementation, you may
    have to invent IDs during merge() which will also need to be persisted,
    since they need to be consistent between instanciation
    """

    def get_checkpoint(self) -> FetchCheckpointBase:
        """
        Returns the last checkpoint passed to merge() after a flush()
        """
        raise NotImplementedError

    def merge(self, delta: FetchDeltaBase) -> None:
        """
        Merge a FetchDeltaBase into the state.

        At the implementation's discretion, it may call flush() or the
        equivalent work.
        """
        raise NotImplementedError

    def flush(self) -> None:
        """
        Finish writing the results of previous merges to persistant state.

        This should also persist the checkpoint.
        """
        raise NotImplementedError

    # TODO - if sticking with this signature, convert to t.NamedTuple
    def get_for_signal_type(
        self, signal_type: t.Type[SignalType]
    ) -> t.List[t.Tuple[str, int]]:
        """
        Get as a map of SignalType.name() => (signal, MetataData ID).

        If the underlying API doesn't support IDs, one solution

        It's assumed that signal is unique (all merging has already taken place).

        TODO this currently implies that you are going to load the entire dataset
        into memory, which once we start getting huge amounts of data, might not make
        sense.
        """
        raise NotImplementedError

    def get_metadata_from_id(
        self, metadata_id: int
    ) -> t.Optional[FetchedSignalDataBase]:
        """
        Fetch the metadata from an ID
        """
        raise NotImplementedError
