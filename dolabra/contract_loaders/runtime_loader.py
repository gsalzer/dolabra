import logging
from typing import Text

import mythril.mythril

from dolabra.contract_loaders.file_loader import FileLoader

log = logging.getLogger(__name__)

class RuntimeLoader(FileLoader):
    def __init__(self, path: Text) -> None:
        super().__init__(path)

    def contract(self):        
        try:
            with open(self._file_path, 'rb') as contract_bin:
                bytecode = contract_bin.read().decode()
                print("in bytecode", bytecode)
        except IOError as e:
            log.error('Failed to open contract binary file: %s', e)
            raise IOError('Failed to open contract binary file')
        disassembler = mythril.mythril.MythrilDisassembler()
        disassembler.load_from_bytecode(bytecode,bin_runtime=True)
        assert len(disassembler.contracts) == 1
        return disassembler.contracts[0]

    @classmethod
    def create(cls, **options):
        return cls(options.get('path'))

