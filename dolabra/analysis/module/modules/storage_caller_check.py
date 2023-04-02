import logging
from typing import Optional
from mythril.laser.ethereum.state.global_state import GlobalState
from mythril.laser.smt.bitvec import BitVec

from dolabra.analysis.module.modules.basemodule import BaseModule


log = logging.getLogger(__name__)

class CalldataTaint:
    """ Class to be used as annotation for CALLDATALOAD elements. """

    def __hash__(self):
        return hash(type(self))

    def __eq__(self, other: 'CalldataTaint'):
        return isinstance(other, CalldataTaint)


class StartFunctionTaint:
    """ Class to be used as annotation for the start of the function. """

    def __hash__(self):
        return hash(type(self))

    def __eq__(self, other: 'StartFunctionTaint'):
        return isinstance(other, StartFunctionTaint)
    
class CallerTaint:
    """ Class to be used as annotation for CALLER elements. """

    def __hash__(self):
        return hash(type(self))

    def __eq__(self, other: 'CallerTaint'):
        return isinstance(other, CallerTaint)


class StorageTaint:
    """ Class to be used as annotation for SLOAD elements. """

    def __init__(self, storage_address: Optional[int] = None):
        self.storage_address = storage_address

    def __hash__(self):
        return hash((type(self), self.storage_address))

    def __eq__(self, other: 'StorageTaint'):
        return self.storage_address == other.storage_address


class StorageCallerCheck(BaseModule):
    pattern_name = "StorageCallerCheck"
    #description = "Detects when a contract checks if a tainted input is equal to a stored address before execution."

    pre_hooks = ['JUMPI']
    post_hooks = ['CALLER', 'SLOAD', 'CALLDATALOAD'] 

    def __init__(self):
        self.is_start_of_function = False
        self.essential_operations = set(['SSTORE', 'CALL', 'CALLCODE', 'DELEGATECALL', 'STATICCALL'])
        super().__init__()

    def _contains_both_taints(self, state: GlobalState) -> bool:
        return (CallerTaint() in state.mstate.stack[-2].annotations and
                 self._has_annotation(state.mstate.stack[-2], StorageTaint)) \
                if state else False
                               
    def _analyze(self, state: GlobalState, prev_state: Optional[GlobalState] = None) -> Optional[dict]:
        if prev_state and prev_state.instruction['opcode'] == 'CALLDATALOAD':
            state.mstate.stack[-1].annotate(CalldataTaint())

        if prev_state and prev_state.instruction['opcode'] == 'SLOAD' and prev_state.mstate.stack[-1].symbolic is False:
            index = prev_state.mstate.stack[-1].value
            if index <= 0xFF:
                # Restrict memorizing storage keys that result from some sort of hashing
                # by checking if the index is less than 256.
                state.mstate.stack[-1].annotate(StorageTaint(index))
        elif prev_state and prev_state.instruction['opcode'] == 'CALLER':
            state.mstate.stack[-1].annotate(CallerTaint())

        if state.instruction['opcode'] == 'JUMPI' and self._contains_both_taints(state):            
            storage_address = self._retrieve_storage_address(state.mstate.stack[-2])
            log.info(
                f"Analyzed {state.instruction['opcode']} at address_index {storage_address} in function ({state.environment.active_function_name})"
            )

        return None

    def _retrieve_storage_address(self, bitvec: BitVec) -> Optional[int]:
        """ Helper function to retrieve the *storage_address* attribute from a BitVec instance. """
        for annotation in bitvec.annotations:
            if isinstance(annotation, StorageTaint):
                return annotation.storage_address
        return None

detector = StorageCallerCheck()
