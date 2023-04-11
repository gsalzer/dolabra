from typing import Optional, List

from mythril.analysis.module.base import DetectionModule, EntryPoint
from mythril.support.support_utils import Singleton
from mythril.exceptions import DetectorNotFoundError

from dolabra.analysis.module.modules import PayableFunction, StorageCallerCheck, Getter, Setter

class ModuleLoader(object, metaclass=Singleton):
    def __init__(self):
        self._modules = []
        self._register_modules()

    def register_module(self, detection_module: DetectionModule):
        """Registers a detection module with the module loader"""
        if not isinstance(detection_module, DetectionModule):
            raise ValueError(
                "The passed variable is not a valid detection module")
        self._modules.append(detection_module)

    def get_detection_modules(self,
                              entry_point: Optional[EntryPoint] = None,
                              white_list: Optional[List[str]] = None,
        ) -> List[DetectionModule]:

        result = self._modules[:]

        if white_list:
            available_names = [type(module).__name__ for module in result]

            for name in white_list:
                if name not in available_names:
                    raise DetectorNotFoundError(
                        "Invalid detection module: {}".format(name)
                    )

            result = [
                module for module in result if type(module).__name__ in white_list
            ]

        if entry_point:
            result = [
                module for module in result if module.entry_point == entry_point]

        return result

    def _register_modules(self):
        self._modules.extend(
            [
                PayableFunction(),
                StorageCallerCheck(),
                Getter(),
                Setter()
            ]
        )
