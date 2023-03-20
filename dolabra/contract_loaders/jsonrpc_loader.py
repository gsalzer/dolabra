import logging
import re
from typing import Optional

from mythril.ethereum.interface.rpc.client import EthJsonRpc
from mythril.disassembler.disassembly import Disassembly
from mythril.support.loader import DynLoader

from dolabra.contract_loaders.contract_loader import ContractLoader

log = logging.getLogger(__name__)

class JsonRpcLoader(ContractLoader):
    def __init__(self, address: str, rpc: Optional[str] = None):
        assert address is not None, "No contract address provided"

        if rpc is None:
            eth_json_rpc = EthJsonRpc()
        else:
            match = re.match(r'(http(s)?:\/\/)?([a-zA-Z0-9\.\-]+)(:([0-9]+))?(\/.+)?', rpc)
            if match:
                host = match.group(3)
                port = match.group(5) if match.group(4) else None
                path = match.group(6) if match.group(6) else ''
                tls = bool(match.group(2))
                log.debug('Parsed RPC provider params: host=%s, port=%s, tls=%r, path=%s', host, port, tls, path)
                eth_json_rpc = EthJsonRpc(host=host + path, port=port, tls=tls)
            else:
                raise Exception('Invalid JSON RPC URL provided: "%s"' % rpc)
        self._dyn_loader = DynLoader(eth_json_rpc)
        self._address = address

    @property
    def dyn_loader(self) -> DynLoader:
        return self._dyn_loader

    @property
    def address(self) -> str:
        return self._address

    def disassembly(self) -> Optional[Disassembly]:
        return self.dyn_loader.dynld(self.address)
