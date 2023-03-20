from abc import ABC, abstractmethod
from typing import Optional

from mythril.disassembler.disassembly import Disassembly

class ContractLoader(ABC):

    @abstractmethod
    def disassembly(self) -> Optional[Disassembly]:
        pass