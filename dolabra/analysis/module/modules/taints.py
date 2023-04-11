from typing import Optional

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
    
class StorageLoadTaint:
    """ Class to be used as annotation for SLOAD elements. """

    def __init__(self, storage_address: Optional[int] = None):
        self.storage_address = storage_address

    def __hash__(self):
        return hash((type(self), self.storage_address))

    def __eq__(self, other: 'StorageLoadTaint'):
        return isinstance(other, StorageLoadTaint) and self.storage_address == other.storage_address
    
class StorageSaveTaint:
    """ Class to be used as annotation for SSTORE elements. """

    def __init__(self, storage_address: Optional[int] = None):
        self.storage_address = storage_address

    def __hash__(self):
        return hash((type(self), self.storage_address))

    def __eq__(self, other: 'StorageSaveTaint'):
        return isinstance(other, StorageSaveTaint) and self.storage_address == other.storage_address