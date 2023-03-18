// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleContract {
    uint256 public value;

    constructor() {
        value = 42;
    }

    function setValue(uint256 newValue) public {
        value = newValue;
    }

    function getValue() public view returns (uint256) {
        return value;
    }

    function payableFunction() public payable {
        require(msg.value > 0, "No ether sent.");
        // Perform any logic here if required
    }
}
