import logging

from dolabra.contract_loaders.file_loader import FileLoader
from mythril.ethereum.evmcontract import EVMContract

log = logging.getLogger(__name__)

class BinaryLoader(FileLoader):
    def contract(self) -> EVMContract:
        try:
            with self._file_path.open() as contract_bin:
                bytecode = contract_bin.read()
        except IOError as e:
            log.error('Failed to open contract binary file: %s', e)
            raise IOError('Failed to open contract binary file')
        return EVMContract(creation_code=bytecode)
