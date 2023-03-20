import time
import logging
from typing import Optional, Text, Union

import sys
from mythril.ethereum import util
from mythril.ethereum.interface.rpc.client import EthJsonRpc
from mythril.support.loader import DynLoader
from mythril.analysis.symbolic import SymExecWrapper
from mythril.analysis.report import Report

# Import custom detection modules
from dolabra.analysis.payable import PayableFunction
from dolabra.logger.log_manager import setup_logger
from dolabra.contract_loaders.file_loader import FileLoader
from dolabra.contract_loaders.jsonrpc_loader import JsonRpcLoader

# laser imports
from mythril.laser.ethereum import svm
from mythril.laser.ethereum.state.world_state import WorldState
from mythril.laser.ethereum.strategy.extensions.bounded_loops import BoundedLoopsStrategy
from mythril.laser.plugin.loader import LaserPluginLoader
from mythril.support.loader import DynLoader

from mythril.laser.plugin.plugins import (
    MutationPrunerBuilder,
    DependencyPrunerBuilder,
    CoveragePluginBuilder,
    InstructionProfilerBuilder,
)

setup_logger()
log = logging.getLogger(__name__)

class SymbolicWrapper:
    def __init__(self, contract):
        self.contract = contract

    def load_contract(self, contract):
        if contract is not None:
            if isinstance(contract, FileLoader):
                return contract.contract().creation_disassembly.bytecode
            elif isinstance(contract, JsonRpcLoader):
                target_address = contract.address
                dyn_loader = contract.dyn_loader
            else:
                raise ValueError('Invalid type for contract parameter')    

    def run_analysis(self):
        contract = self.contract
        if contract is not None:
            if isinstance(contract, FileLoader):
                bytecode = contract.contract().creation_disassembly.bytecode
            elif isinstance(contract, JsonRpcLoader):
                contract_address = contract.address
                dyn_loader = contract.dyn_loader
            else:
                raise ValueError('Invalid type for contract parameter')
            
        # TODO: handle the case where contract is None/bytecode is None
        # Set up the Ethereum JSON-RPC client
        #eth_rpc_client = EthJsonRpc("127.0.0.1", "7545")

        # Get the deployed contract's bytecode
        #deployed_bytecode = eth_rpc_client.eth_getCode(contract_address)
        # log.info("bytecode: %s", deployed_bytecode)
        #dyn_loader = DynLoader(eth_rpc_client)

        # LaserWrapper
        laser = svm.LaserEVM(dynamic_loader=dyn_loader, execution_timeout=60,
                            max_depth=128, requires_statespace=False)
        world_state = WorldState()
        world_state.accounts_exist_or_load(contract_address, dyn_loader)

        current_strategy = PayableFunction()
        for hook in current_strategy.pre_hooks:
            laser.register_hooks('pre', {hook: [current_strategy.execute]})

        # Load laser plugins
        laser.extend_strategy(BoundedLoopsStrategy, loop_bound=3)
        plugin_loader = LaserPluginLoader()
        plugin_loader.load(CoveragePluginBuilder())
        plugin_loader.load(MutationPrunerBuilder())
        plugin_loader.load(InstructionProfilerBuilder())
        plugin_loader.load(DependencyPrunerBuilder())
        plugin_loader.instrument_virtual_machine(laser, None)

        # Run symbolic execution
        start_time = time.time()
        laser.sym_exec(creation_code=None,
                    contract_name='Unknown',
                    world_state=world_state,
                    target_address=int(contract_address, 16) if contract_address else None)
        log.info('Symbolic execution finished in %.2f seconds.',
                time.time() - start_time)
