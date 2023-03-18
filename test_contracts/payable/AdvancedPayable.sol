pragma solidity ^0.8.0;

contract AdvancedPayable {
    uint256 public storedData;

    event DataStored(uint256 data);

    constructor(uint256 initialValue) {
        storedData = initialValue;
    }

    function set(uint256 x) public {
        storedData = x;
        emit DataStored(x);
    }

    function get() public view returns (uint256) {
        return storedData;
    }

    function increment() public payable {
        require(msg.value > 0, "Value must be greater than 0");
        storedData += 1;
    }

    function decrement() public {
        storedData -= 1;
    }

    function doubleValue() public {
        storedData *= 2;
    }

    function reset() public payable {
        require(msg.value > 0, "Value must be greater than 0");
        storedData = 0;
    }

    function donate() public payable {
        require(msg.value > 0, "Donation must be greater than 0");
    }

    receive() external payable {
        emit DataStored(storedData);
    }

    fallback() external payable {
        emit DataStored(storedData);
    }
}
