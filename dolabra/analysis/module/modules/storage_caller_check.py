import logging
from typing import Optional
from mythril.laser.ethereum.state.global_state import GlobalState
from mythril.laser.smt.bitvec import BitVec
from mythril.analysis.module.base import DetectionModule, EntryPoint

from mythril.analysis.potential_issues import (
    PotentialIssue,
    get_potential_issues_annotation,
)

log = logging.getLogger(__name__)

class Caller:
    """ Class to be used as annotation for CALLER elements. """

    def __hash__(self):
        return hash(type(self))

    def __eq__(self, other: 'Caller'):
        return isinstance(other, Caller)


class Storage:
    """ Class to be used for SLOAD elements. """

    def __init__(self, storage_address: Optional[int] = None):
        self.storage_address = storage_address

    def __hash__(self):
        return hash((type(self), self.storage_address))

    def __eq__(self, other: 'Storage'):
        return self.storage_address == other.storage_address


class StorageCallerCheck(DetectionModule):
    name = "StorageCallerCheck"
    description = "TODO"
    entry_point = EntryPoint.CALLBACK

    def __init__(self):
        self.pre_hooks = ['JUMPI']
        self.post_hooks = ['CALLER', 'SLOAD', 'EQ']
        super().__init__()

    def _execute(self, state: GlobalState) -> None:
        potential_issues = self._analyze_state(state)

        annotation = get_potential_issues_annotation(state)
        annotation.potential_issues.extend(potential_issues)    

    def _analyze_state(self, state: GlobalState, prev_state: Optional[GlobalState] = None) -> Optional[dict]:
        if prev_state and prev_state.instruction['opcode'] == 'CALLER':
            state.mstate.stack[-1].annotate(Caller())
        elif prev_state and prev_state.instruction['opcode'] == 'SLOAD':
            state.mstate.stack[-1].annotate(Storage(prev_state.mstate.stack[-1].value))

        log.info(
                f"Analyzed {state.instruction['opcode']} at address {state.instruction['address']} in function ({state.environment.active_function_name})"
            )

        if state.instruction['opcode'] == 'EQ':
            if (Caller() in state.mstate.stack[-1].annotations and
                    self._has_annotation(state.mstate.stack[-2], Storage)):
                state.mstate.stack[-1].annotate(Caller())
            elif (Caller() in state.mstate.stack[-2].annotations and
                  self._has_annotation(state.mstate.stack[-1], Storage)):
                state.mstate.stack[-2].annotate(Caller())

        if state.instruction['opcode'] == 'JUMPI' and Caller() in state.mstate.stack[-2].annotations:
            storage_address = self._retrieve_storage_address(state.mstate.stack[-2])

            function_id = state.environment.active_function_name

            log.info(
                f"Encountered {state.instruction['opcode']} at address {state.instruction['address']} in function ({function_id})"
            )
            
            potential_issue = PotentialIssue(
                contract=state.environment.active_account.contract_name,
                function_name=state.environment.active_function_name,
                address=storage_address,
                swc_id="N/A",
                title="Storage Caller Check Analysis",
                severity="Neutral",
                description_head="_index_caller_check",
                bytecode=state.environment.code.bytecode,
                detector=self
            )
            return [potential_issue]

        return []

    def _has_annotation(self, element, annotation_class):
        for annotation in element.annotations:
            if isinstance(annotation, annotation_class):
                return True
        return False

    def _retrieve_storage_address(self, bitvec: BitVec) -> Optional[int]:
        """ Helper function to retrieve the *storage_address* attribute from a BitVec instance. """
        for annotation in bitvec.annotations:
            if isinstance(annotation, Storage):
                return annotation.storage_address
        return None

detector = StorageCallerCheck()