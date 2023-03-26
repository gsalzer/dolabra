pragma solidity ^0.8.0;

contract StorageCallerCheck {
    address private owner;
    mapping(address => uint256) private balances;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not the owner");
        _;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }

    function setOwner(address newOwner) public onlyOwner {
        owner = newOwner;
    }

    function getBalance(address account) public view returns (uint256) {
        return balances[account];
    }

    function getOwner() public view returns (address) {
        return owner;
    }
}