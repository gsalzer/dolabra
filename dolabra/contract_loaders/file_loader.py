from pathlib import Path
from typing import Union
from abc import ABC, abstractmethod

from mythril.ethereum.evmcontract import EVMContract
from mythril.disassembler.disassembly import Disassembly

from dolabra.contract_loaders.contract_loader import ContractLoader

class FileLoader(ContractLoader, ABC):
    def __init__(self, file_path: Union[str, Path]):
        self._file_path = Path(file_path)

    def disassembly(self) -> Disassembly:
        return self.contract().disassembly

    @abstractmethod
    def contract(self) -> EVMContract:
        pass
