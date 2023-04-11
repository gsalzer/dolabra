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
    
class DupTwoTaint:
    """ Class to be used as annotation for DUP1 elements. """

    def __hash__(self):
        return hash(type(self))

    def __eq__(self, other: 'DupTwoTaint'):
        return isinstance(other, DupTwoTaint)    
    
class SwapOneTaint:
    """ Class to be used as annotation for SWAP1 elements. """

    def __hash__(self):
        return hash(type(self))

    def __eq__(self, other: 'SwapOneTaint'):
        return isinstance(other, SwapOneTaint)   

class StorageSaveTaint:
    """ Class to be used as annotation for SSTORE elements. """

    def __init__(self, storage_address: Optional[int] = None):
        self.storage_address = storage_address

    def __hash__(self):
        return hash((type(self), self.storage_address))

    def __eq__(self, other: 'StorageSaveTaint'):
        return isinstance(other, StorageSaveTaint) and self.storage_address == other.storage_address


class Setter(BaseModule):
    pattern_name = "Setter"

    post_hooks = ['DUP1', 'PUSH1', 'DUP2', 'SWAP1', 'SSTORE'] 

    def __init__(self):
        self.already_storage_tainted_sign = []
        super().__init__()

    def _analyze(self, state: GlobalState, prev_state: Optional[GlobalState] = None) -> Optional[dict]:
        if prev_state and prev_state.instruction['opcode'] == 'DUP1':
            state.mstate.stack[-1].annotate(DupOneTaint())

        elif prev_state and prev_state.instruction['opcode'] == 'PUSH1':
            if len(state.mstate.stack) > 1 and DupOneTaint() in state.mstate.stack[-2].annotations:
                state.mstate.stack[-2].annotate(PushOneTaint())

        elif prev_state and prev_state.instruction['opcode'] == 'DUP2' and {DupOneTaint(), PushOneTaint()}.issubset(state.mstate.stack[-1].annotations):
            state.mstate.stack[-1].annotate(DupTwoTaint())

        elif prev_state and prev_state.instruction['opcode'] == 'SWAP1' and {DupOneTaint(), PushOneTaint(), DupTwoTaint()}.issubset(state.mstate.stack[-1].annotations):
            state.mstate.stack[-1].annotate(SwapOneTaint())    

        elif prev_state and prev_state.instruction['opcode'] == 'SSTORE':            
            if len(state.mstate.stack) >= 1:
                current_function = state.environment.active_function_name
                # loop through the stack to find the DUP1 element, there can be mulitple PUSH1s setting the indexes
                for stack_index in range(len(state.mstate.stack)):                                        
                    if {DupOneTaint(), PushOneTaint(), DupTwoTaint(), SwapOneTaint()}.issubset(state.mstate.stack[stack_index].annotations) and current_function not in self.already_storage_tainted_sign:                        
                        state.mstate.stack[stack_index].annotate(StorageSaveTaint())
                        self.already_storage_tainted_sign.append(current_function)
                        return {'contract': state.environment.active_account.contract_name, 'pattern': self.pattern_name, 'function_name': current_function}             

        return None
