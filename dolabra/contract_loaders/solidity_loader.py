from pathlib import Path
from typing import Union, Optional
from mythril.ethereum.evmcontract import EVMContract
from mythril.solidity.soliditycontract import SolidityContract

from dolabra.contract_loaders.file_loader import FileLoader

class SolidityLoader(FileLoader):
    def __init__(self, file_path: Union[str, Path], solc: Optional[str] = 'solc'):
        super().__init__(file_path)
        self._solc = solc

    def contract(self) -> EVMContract:
        return SolidityContract(str(self._file_path), solc_binary=self._solc)
    
    @classmethod
    def create(cls, **options):
        return cls(options.get('path'), solc=options.get('solc'))

    


