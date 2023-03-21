import logging
from typing import Text
from dolabra.contract_loaders.file_loader import FileLoader

from mythril.ethereum.evmcontract import EVMContract

log = logging.getLogger(__name__)

class BinaryLoader(FileLoader):
    def __init__(self, path: Text) -> None:
        super().__init__(path)

    def contract(self) -> EVMContract:
        try:
            with open(self._file_path, 'rb') as contract_bin:
                bytecode = contract_bin.read()
        except IOError as e:
            log.error('Failed to open contract binary file: %s', e)
            raise IOError('Failed to open contract binary file')
        return EVMContract(creation_code=bytecode)

    @classmethod
    def create(cls, **options):
        return cls(options.get('path'))

