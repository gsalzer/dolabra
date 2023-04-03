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

class InputTaint:
    """ Class to be used as annotation for tainted input elements. """

    def __init__(self, taint_id: str):
        self.taint_id = taint_id

    def __hash__(self):
        return hash((type(self), self.taint_id))

    def __eq__(self, other: 'InputTaint'):
        return isinstance(other, InputTaint) and self.taint_id == other.taint_id


class StorageTaint:
    """ Class to be used as annotation for SLOAD elements with tainted input. """

    def __init__(self, taint_id: str):
        self.taint_id = taint_id

    def __hash__(self):
        return hash((type(self), self.taint_id))

    def __eq__(self, other: 'StorageTaint'):
        return isinstance(other, StorageTaint) and self.taint_id == other.taint_id


class StorageCallerCheck(DetectionModule):
    name = "StorageCallerCheck"
    description = "Detects when a contract checks if a tainted input is equal to a stored address before execution."
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
            state.mstate.stack[-1].annotate(InputTaint('caller'))
        elif prev_state and prev_state.instruction['opcode'] == 'SLOAD':
            if self._has_annotation(prev_state.mstate.stack[-1], InputTaint):
                taint_id = self._get_annotation(prev_state.mstate.stack[-1], InputTaint).taint_id
                state.mstate.stack[-1].annotate(StorageTaint(taint_id))

        log.info(
                f"Analyzed {state.instruction['opcode']} at address {state.instruction['address']} in function ({state.environment.active_function_name})"
            )

        if state.instruction['opcode'] == 'EQ':
            if (self._has_annotation(state.mstate.stack[-1], StorageTaint) and
                    self._has_annotation(state.mstate.stack[-2], InputTaint)):
                storage_taint = self._get_annotation(state.mstate.stack[-1], StorageTaint)
                input_taint = self._get_annotation(state.mstate.stack[-2], InputTaint)
                if storage_taint.taint_id != input_taint.taint_id:
                    state.mstate.stack[-1].annotate(InputTaint(input_taint.taint_id))
            elif (self._has_annotation(state.mstate.stack[-2], StorageTaint) and
                self._has_annotation(state.mstate.stack[-1], InputTaint)):
                storage_taint = self._get_annotation(state.mstate.stack[-2], StorageTaint)
                input_taint = self._get_annotation(state.mstate.stack[-1], InputTaint)
                if storage_taint.taint_id != input_taint.taint_id:
                    state.mstate.stack[-1].annotate(InputTaint(storage_taint.taint_id))

            if (self._has_annotation(state.mstate.stack[-1], InputTaint) and
                self._has_annotation(state.mstate.stack[-2], StorageTaint)):

                function_id = state.environment.active_function_name

                log.info(
                    f"Encountered {state.instruction['opcode']} at address {state.instruction['address']} in function ({function_id})"
                )
            
                issue = PotentialIssue(
                    contract=state.environment.active_account.contract_name,
                    function_name=state.environment.active_function_name,
                    address=state.get_current_instruction()['address'],
                    swc_id="SWC-XXXX",
                    title="Storage Caller Check",
                    severity="Low",
                    description="Detected a condition where a tainted input is checked against a stored address.",
                    bytecode=state.environment.code.bytecode,
                )
                return [issue]
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
