"""
 This file is part of nucypher.

 nucypher is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 nucypher is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with nucypher.  If not, see <https://www.gnu.org/licenses/>.
"""


from collections import Counter

import maya
from abc import ABC, abstractmethod
from constant_sorrow.constants import (
    UNVERIFIED,
    VERIFIED,
    UNAVAILABLE,
    SUSPICIOUS,
    UNSTAKED,
    INVALID
)


class PruningStrategy(ABC):

    @abstractmethod
    def __call__(self, node: "Teacher") -> bool:
        """
        Return True to keep a node or False to Erase
        NOTE: This function *must* return a boolean to operate properly.
        """
        raise NotImplementedError

    def reset(self, node: "Teacher") -> None:
        pass


class Accept(PruningStrategy):

    def __call__(self, node: "Teacher") -> bool:
        """Always Keep"""
        return True


class Reject(PruningStrategy):

    def __call__(self, node: "Teacher") -> bool:
        """Indicate a node can be deleted now."""
        return False


class StaleCheck(PruningStrategy):

    def __init__(self, max_seconds: int):
        self.max_seconds = max_seconds
        super().__init__()

    def __call__(self, node: "Teacher") -> bool:
        if node.last_seen:
            delta = maya.now().epoch - node.last_seen.epoch
            return delta < self.max_seconds
        return True


class MaxAttempts(PruningStrategy):

    def __init__(self, max_attempts: int):
        self.attempts = Counter()
        self.max_attempts = max_attempts
        super().__init__()

    def __call__(self, node: "Teacher") -> bool:
        self.attempts[node.checksum_address] += 1
        if self.attempts[node.checksum_address] > self.max_attempts:
            self.reset(node)  # stop tracking.
            return False
        return True

    def reset(self, node: "Teacher") -> None:
        del self.attempts[node.checksum_address]


BUCKETS = (

    #
    # Static buckets
    #

    # NUCYPHER / SUPERNODE / SEEDNODE,
    UNVERIFIED,
    VERIFIED,
    # TRASH  # TODO: Consider using a TRASH label.


    #
    # Pruned buckets
    #

    UNAVAILABLE,
    SUSPICIOUS,
    UNSTAKED,
    INVALID,
)

PRUNING_STRATEGIES = {
    UNAVAILABLE: [
        StaleCheck(max_seconds=60 * 60 * 72),
        MaxAttempts(max_attempts=20)
    ],
    SUSPICIOUS: [
        Reject()  # TODO: Persist rejection to prevent re-entry?
    ],
    UNSTAKED: [
        Accept()  # TODO: Criteria for removal?
    ],
    INVALID: [
        Accept()  # TODO: Reject instead?
    ]
}

VERIFICATION_SORTING_WEIGHTS = {
    VERIFIED: 2,
    UNVERIFIED: 4,
    UNAVAILABLE: 3,
    SUSPICIOUS: 1,
    UNSTAKED: 1
}
