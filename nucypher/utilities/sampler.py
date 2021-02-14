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

from bisect import bisect_right

from itertools import accumulate
from typing import Dict, Any


class WeightedSampler:
    """
    Samples random elements with probabilities proportional to given weights.
    """

    def __init__(self, weighted_elements: Dict[Any, int]):
        if weighted_elements:
            elements, weights = zip(*weighted_elements.items())
        else:
            elements, weights = [], []
        self.totals = list(accumulate(weights))
        self.elements = elements
        self.__length = len(self.totals)

    def sample_no_replacement(self, rng, quantity: int) -> list:
        """
        Samples ``quantity`` of elements from the internal array.
        The probablity of an element to appear is proportional
        to the weight provided to the constructor.

        The elements will not repeat; every time an element is sampled its weight is set to 0.
        (does not mutate the object and only applies to the current invocation of the method).
        """

        if quantity == 0:
            return []

        if quantity > len(self):
            raise ValueError("Cannot sample more than the total amount of elements without replacement")

        samples = []

        for i in range(quantity):
            position = rng.randint(0, self.totals[-1] - 1)
            idx = bisect_right(self.totals, position)
            samples.append(self.elements[idx])

            # Adjust the totals so that they correspond
            # to the weight of the element `idx` being set to 0.
            prev_total = self.totals[idx - 1] if idx > 0 else 0
            weight = self.totals[idx] - prev_total
            for j in range(idx, len(self.totals)):
                self.totals[j] -= weight

        self.__length -= quantity

        return samples

    def __len__(self):
        return self.__length
