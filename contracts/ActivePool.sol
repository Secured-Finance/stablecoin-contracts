// SPDX-License-Identifier: MIT

pragma solidity 0.7.6;

import "./Interfaces/IActivePool.sol";
import "./Dependencies/OpenZeppelin/access/OwnableUpgradeable.sol";
import "./Dependencies/OpenZeppelin/math/SafeMath.sol";
import "./Dependencies/CheckContract.sol";

/*
 * The Active Pool holds the FIL collateral and debt (but not debt tokens) for all active troves.
 *
 * When a trove is liquidated, it's FIL and debt are transferred from the Active Pool, to either the
 * Stability Pool, the Default Pool, or both, depending on the liquidation conditions.
 *
 */
contract ActivePool is OwnableUpgradeable, CheckContract, IActivePool {
    using SafeMath for uint256;

    string public constant NAME = "ActivePool";

    address public borrowerOperationsAddress;
    address public troveManagerAddress;
    address public stabilityPoolAddress;
    address public defaultPoolAddress;
    uint256 internal FIL; // deposited filecoin tracker
    uint256 internal debt;

    constructor() initializer {}

    // --- Contract setters ---

    function initialize(
        address _borrowerOperationsAddress,
        address _troveManagerAddress,
        address _stabilityPoolAddress,
        address _defaultPoolAddress
    ) external initializer {
        __Ownable_init();
        _setAddresses(
            _borrowerOperationsAddress,
            _troveManagerAddress,
            _stabilityPoolAddress,
            _defaultPoolAddress
        );
    }

    function _setAddresses(
        address _borrowerOperationsAddress,
        address _troveManagerAddress,
        address _stabilityPoolAddress,
        address _defaultPoolAddress
    ) private {
        checkContract(_borrowerOperationsAddress);
        checkContract(_troveManagerAddress);
        checkContract(_stabilityPoolAddress);
        checkContract(_defaultPoolAddress);

        borrowerOperationsAddress = _borrowerOperationsAddress;
        troveManagerAddress = _troveManagerAddress;
        stabilityPoolAddress = _stabilityPoolAddress;
        defaultPoolAddress = _defaultPoolAddress;

        emit BorrowerOperationsAddressChanged(_borrowerOperationsAddress);
        emit TroveManagerAddressChanged(_troveManagerAddress);
        emit StabilityPoolAddressChanged(_stabilityPoolAddress);
        emit DefaultPoolAddressChanged(_defaultPoolAddress);
    }

    // --- Getters for public variables. Required by IPool interface ---

    /*
     * Returns the FIL state variable.
     *
     * Not necessarily equal to the the contract's raw FIL balance - filecoin can be forcibly sent to contracts.
     */
    function getFIL() external view override returns (uint) {
        return FIL;
    }

    function getDebt() external view override returns (uint) {
        return debt;
    }

    // --- Pool functionality ---

    function sendFIL(address _account, uint _amount) external override {
        require(_account != address(0), "ActivePool: account cannot be zero address");

        _requireCallerIsBOorTroveMorSP();
        FIL = FIL.sub(_amount);
        emit ActivePoolFILBalanceUpdated(FIL);
        emit FILSent(_account, _amount);

        (bool success, ) = _account.call{value: _amount}("");
        require(success, "ActivePool: sending FIL failed");
    }

    function increaseDebt(uint _amount) external override {
        _requireCallerIsBOorTroveM();
        debt = debt.add(_amount);
        emit ActivePoolDebtUpdated(debt);
    }

    function decreaseDebt(uint _amount) external override {
        _requireCallerIsBOorTroveMorSP();
        debt = debt.sub(_amount);
        emit ActivePoolDebtUpdated(debt);
    }

    // --- 'require' functions ---

    function _requireCallerIsBorrowerOperationsOrDefaultPool() internal view {
        require(
            msg.sender == borrowerOperationsAddress || msg.sender == defaultPoolAddress,
            "ActivePool: Caller is neither BO nor Default Pool"
        );
    }

    function _requireCallerIsBOorTroveMorSP() internal view {
        require(
            msg.sender == borrowerOperationsAddress ||
                msg.sender == troveManagerAddress ||
                msg.sender == stabilityPoolAddress,
            "ActivePool: Caller is neither BorrowerOperations nor TroveManager nor StabilityPool"
        );
    }

    function _requireCallerIsBOorTroveM() internal view {
        require(
            msg.sender == borrowerOperationsAddress || msg.sender == troveManagerAddress,
            "ActivePool: Caller is neither BorrowerOperations nor TroveManager"
        );
    }

    // --- Fallback function ---

    receive() external payable {
        _requireCallerIsBorrowerOperationsOrDefaultPool();
        FIL = FIL.add(msg.value);
        emit ActivePoolFILBalanceUpdated(FIL);
    }
}
