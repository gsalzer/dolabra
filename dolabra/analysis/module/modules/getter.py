import logging
from typing import Optional
from mythril.laser.ethereum.state.global_state import GlobalState

from dolabra.analysis.module.modules.basemodule import BaseModule


log = logging.getLogger(__name__)
    
class PushOneTaint:
    """ Class to be used as annotation for PUSH1 elements. """

    def __hash__(self):
        return hash(type(self))

    def __eq__(self, other: 'PushOneTaint'):
        return isinstance(other, PushOneTaint)        
    
class DupOneTaint:
    """ Class to be used as annotation for DUP1 elements. """

    def __hash__(self):
        return hash(type(self))

    def __eq__(self, other: 'DupOneTaint'):
        return isinstance(other, DupOneTaint)

class StorageTaint:
    """ Class to be used as annotation for SLOAD elements. """

    def __init__(self, storage_address: Optional[int] = None):
        self.storage_address = storage_address

    def __hash__(self):
        return hash((type(self), self.storage_address))

    def __eq__(self, other: 'StorageTaint'):
        return isinstance(other, StorageTaint) and self.storage_address == other.storage_address


class Getter(BaseModule):
    pattern_name = "Getter"

    post_hooks = ['PUSH1', 'DUP1', 'SLOAD'] 

    def __init__(self):
        self.already_storage_tainted_sign = []
        super().__init__()

    def _analyze(self, state: GlobalState, prev_state: Optional[GlobalState] = None) -> Optional[dict]:
        if prev_state and prev_state.instruction['opcode'] == 'PUSH1':
            state.mstate.stack[-1].annotate(PushOneTaint())

        elif prev_state and prev_state.instruction['opcode'] == 'DUP1' and PushOneTaint() in state.mstate.stack[-1].annotations:
            state.mstate.stack[-1].annotate(DupOneTaint())

        elif prev_state and prev_state.instruction['opcode'] == 'SLOAD':            
            if len(state.mstate.stack) >= 1:
                current_function = state.environment.active_function_name
                # loop through the stack to find the DUP1 element, there can be mulitple PUSH1s setting the indexes
                for stack_index in range(len(state.mstate.stack)):                                        
                    if DupOneTaint() in state.mstate.stack[stack_index].annotations and current_function not in self.already_storage_tainted_sign:                        
                        state.mstate.stack[stack_index].annotate(StorageTaint())
                        self.already_storage_tainted_sign.append(current_function)
                        return {'contract': state.environment.active_account.contract_name, 'pattern': self.pattern_name, 'function_name': current_function}             

        return None
