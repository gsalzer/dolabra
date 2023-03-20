import time
import logging

import sys
from mythril.ethereum import util
from mythril.ethereum.interface.rpc.client import EthJsonRpc
from mythril.support.loader import DynLoader
from mythril.analysis.symbolic import SymExecWrapper
from mythril.analysis.report import Report

# Import custom detection modules
from dolabra.analysis.payable import PayableFunction
from dolabra.logger.log_manager import setup_logger

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
    def __init__(self, contract_address):
        self.contract_address = contract_address

    def run_analysis(self):
        # Contract address
        contract_address = self.contract_address
        # contract_address = "0xd54dc858ba35e03add06ff47d6e920406d014924"
        # contract_address = "0xa3e56a46078ecf299d8d5ec3e59756a9e6efa95e8c5e0574aa75fcc90e6cdddd"

        # Set up the Ethereum JSON-RPC client
        eth_rpc_client = EthJsonRpc("127.0.0.1", "7545")

        # Get the deployed contract's bytecode
        deployed_bytecode = eth_rpc_client.eth_getCode(contract_address)
        # log.info("bytecode: %s", deployed_bytecode)
        dyn_loader = DynLoader(eth_rpc_client)

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
