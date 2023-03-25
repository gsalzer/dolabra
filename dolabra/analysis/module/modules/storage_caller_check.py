import logging
from mythril.analysis.module.base import DetectionModule, EntryPoint
from mythril.laser.ethereum.state.global_state import GlobalState
from mythril.analysis.potential_issues import (
    PotentialIssue,
    get_potential_issues_annotation,
)

log = logging.getLogger(__name__)


class StorageCallerCheck(DetectionModule):
    name = "Storage Caller Check"
    description = "Check if a storage cell value is compared to the caller address at the beginning of public functions (authorization pattern)"
    entrypoint = EntryPoint.CALLBACK
    pre_hooks = ["SLOAD", "CALLER", "EQ", "JUMPDEST"]

    def __init__(self):
        super().__init__()
        self.storage_loaded = False
        self.caller_loaded = False
        self.authorization_check = False
        self.after_jumpdest = False

    def _execute(self, state: GlobalState) -> None:

        potential_issues = self._analyze_state(state)

        annotation = get_potential_issues_annotation(state)
        annotation.potential_issues.extend(potential_issues)

    def _analyze_state(self, state: GlobalState):

        opcode = state.get_current_instruction()["opcode"]
        address = state.get_current_instruction()["address"]

        if opcode == "JUMPDEST":
            self.after_jumpdest = True

        if opcode == "SLOAD" and self.after_jumpdest:
            self.storage_loaded = True

        if opcode == "CALLER" and self.storage_loaded:
            self.caller_loaded = True

        if (
            opcode == "EQ"
            and self.caller_loaded
            and self.storage_loaded
        ):
            self.authorization_check = True

        log.info(
            f"Encountered {opcode} at address {address} in function ({state.environment.active_function_name})"
        )

        if self.authorization_check:
            potential_issue = PotentialIssue(
                contract=state.environment.active_account.contract_name,
                function_name=state.environment.active_function_name,
                address=address,
                swc_id="N/A",
                title="Storage Caller Check",
                severity="Neutral",
                description_head="A storage cell value is compared to the caller address at the beginning of a public function (authorization pattern).",
                bytecode=state.environment.code.bytecode,
                detector=self
            )

            self.storage_loaded = False
            self.caller_loaded = False
            self.authorization_check = False
            self.after_jumpdest = False

            return [potential_issue]

        else:
            self.storage_loaded = False
            self.caller_loaded = False
            self.authorization_check = False
            self.after_jumpdest = False

            return []

    #TODO: Implement this method based on report strategy
    '''
    def generate_report(self, statespace):
        issues = get_potential_issues_annotation(statespace)
        storage_caller_checks = []

        for issue in issues:
            if issue.title == "Storage Caller Check":
                storage_caller_checks.append(issue)

        return storage_caller_checks
    '''
#TODO: check if it is needed
detector = StorageCallerCheck()