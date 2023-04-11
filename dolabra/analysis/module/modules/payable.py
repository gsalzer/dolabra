import logging
from typing import List

from mythril.analysis import solver
from mythril.analysis.module.base import DetectionModule, EntryPoint
from mythril.exceptions import UnsatError
from mythril.laser.ethereum.state.global_state import GlobalState
from mythril.laser.smt import UGT, symbol_factory

from mythril.analysis.potential_issues import (
    PotentialIssue,
    get_potential_issues_annotation,
)

log = logging.getLogger(__name__)


class PayableFunction(DetectionModule):
    name = "Payable Function Analysis"
    description = "Analyzes payable and non-payable functions."
    entry_point = EntryPoint.CALLBACK
    pre_hooks = ["STOP", "RETURN", "REVERT", "HALT"]

    def __init__(self):
        super().__init__()

    def _execute(self, state: GlobalState) -> None:
        potential_issues = self._analyze_state(state)

        annotation = get_potential_issues_annotation(state)
        annotation.potential_issues.extend(potential_issues)

    def _analyze_state(self, state: GlobalState) -> List[PotentialIssue]:
        opcode = state.get_current_instruction()["opcode"]
        address = state.get_current_instruction()["address"]

        function_id = state.environment.active_function_name

        log.info(
            f"Encountered {opcode} at address {address} in function ({function_id})"
        )

        # Check for payable and non-payable constraints
        constraints_zero_value = state.world_state.constraints + \
            [state.environment.callvalue == 0]
        constraints_non_zero_value = state.world_state.constraints + [
            UGT(state.environment.callvalue, symbol_factory.BitVecVal(0, 256))
        ]

        try:
            solver.get_transaction_sequence(state, constraints_zero_value)
            payable = False
        except UnsatError:
            payable = True

        if not payable:
            try:
                solver.get_transaction_sequence(
                    state, constraints_non_zero_value)
                non_payable = False
            except UnsatError:
                non_payable = True
        else:
            non_payable = False

        if payable and non_payable:
            log.info(
                f"Function ({function_id}) seems to have a programming error (both payable and non-payable)."
            )
            potential_issue = PotentialIssue(
                contract=state.environment.active_account.contract_name,
                function_name=state.environment.active_function_name,
                address=address,
                swc_id="N/A",
                title="Payable Function Analysis",
                severity="Neutral",
                description_head="Function seems to have a programming error (both payable and non-payable).",
                bytecode=state.environment.code.bytecode,
                detector=self
            )
            return [potential_issue]
        else:
            log.info(
                f"Function ({function_id}) is {'payable' if payable else 'non-payable'}."
            )
            return []


detector = PayableFunction()

