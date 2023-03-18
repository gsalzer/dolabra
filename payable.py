import logging
from mythril.analysis import solver
from mythril.analysis.module.base import DetectionModule, EntryPoint
from mythril.analysis.report import Issue
from mythril.exceptions import UnsatError
from mythril.laser.ethereum.state.global_state import GlobalState
from mythril.laser.ethereum.transaction.symbolic import ACTORS
from mythril.laser.smt import And, UGT, symbol_factory

log = logging.getLogger(__name__)


class PayableFunction(DetectionModule):
    name = "Payable Function Analysis"
    description = "Analyzes payable and non-payable functions."
    entry_point = EntryPoint.CALLBACK
    pre_hooks = ["STOP", "RETURN", "REVERT", "HALT"]

    def __init__(self):
        super().__init__()

    def _execute(self, state: GlobalState) -> None:
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
        else:
            log.info(
                f"Function ({function_id}) is {'payable' if payable else 'non-payable'}."
            )

        return


detector = PayableFunction()
