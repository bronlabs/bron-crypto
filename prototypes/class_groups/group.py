from abc import ABC, abstractmethod
from copy import copy
from typing import Self


class AbelianGroup(ABC):
    @classmethod
    @abstractmethod
    def zero(cls) -> Self:
        ...

    @classmethod
    @abstractmethod
    def random(cls) -> Self:
        ...

    @abstractmethod
    def __add__(self, other: Self) -> Self:
        ...

    @abstractmethod
    def __neg__(self) -> Self:
        ...

    @abstractmethod
    def __eq__(self, other: Self) -> bool:
        ...

    @abstractmethod
    def __copy__(self) -> Self:
        ...

    def __sub__(self, other: Self) -> Self:
        return self + -other

    def __mul__(self, other: int) -> Self:
        if other == 0:
            return self.zero()
        if other < 0:
            return self * -other

        res = self.zero()
        tmp = self
        while other != 0:
            if (other % 2) == 1:
                res = res + tmp
            tmp = tmp + tmp
            other >>= 1
        return res

    def __rmul__(self, other: Self) -> Self:
        return self * other

def element_order(e: AbelianGroup) -> int:
    identity = e.zero()
    order = 1

    i = copy(e)
    while i != identity:
        order += 1
        i = i + e
    return order
