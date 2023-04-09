import logging

from abc import ABC, abstractmethod
from typing import List, Optional, Set, Text, Type, Dict

from mythril.laser.ethereum.state.global_state import GlobalState
from mythril.laser.smt.bitvec import BitVec

log = logging.getLogger(__name__)

class BaseModule(ABC):
    """
    Base class for contract analysis modules.

    When creating a new analysis strategy by subclassing this base class, override the *_analyze()* function.
    """

    pattern_name = ''
    #report_title = ''
    #report_description = ''

    pre_hooks: List[Text] = []
    post_hooks: List[Text] = []

    def __init__(self):
        self.cache: Set[Text] = set()
        self.results: List[Dict[Text, Text]] = []

    def reset(self) -> None:
        self.cache = set()
        self.results = []

    #TODO: generate report

    def execute(self, state: GlobalState):
        """ Execute analysis strategy on the given state. """
        if state.environment.active_function_name in self.cache:
            return None
        log.debug('Executing analysis module %s', type(self).__name__)
        result = self._analyze(state, state.node.states[-1] if len(state.node.states) > 0 and state is not state.node.states[-1] else None)
        if result is not None:
            log.info('Analysis strategy %s got a hit in function %s', type(self).__name__, result['function_name'])
            self.results.append(result)
            self.cache.add(state.environment.active_function_name)
        return result

    @abstractmethod
    def _analyze(self, state: GlobalState, prev_state: Optional[GlobalState] = None):
        """ Actual implementation of the analysis module. Override this when inheriting BaseModule. """
        pass

    def _has_annotation(self, bitvec: BitVec, annotation_type: Type) -> bool:
        """ Returns true if *bitvec* contains an annotation of type *annotation_type* """
        for annotation in bitvec.annotations:
            if isinstance(annotation, annotation_type):
                return True
        return False
