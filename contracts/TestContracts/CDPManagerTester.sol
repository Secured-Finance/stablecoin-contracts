// SPDX-License-Identifier: MIT

pragma solidity 0.7.6;

import "../TroveManager.sol";

/* Tester contract inherits from TroveManager, and provides external functions 
for testing the parent's internal functions. */

contract TroveManagerTester is TroveManager {
    constructor(
        uint _gasCompensation,
        uint _minNetDebt,
        uint _bootstrapPeriod
    ) TroveManager(_gasCompensation, _minNetDebt, _bootstrapPeriod) {}

    function computeICR(uint _coll, uint _debt, uint _price) external pure returns (uint) {
        return ProtocolMath._computeCR(_coll, _debt, _price);
    }

    function getCollGasCompensation(uint _coll) external pure returns (uint) {
        return _getCollGasCompensation(_coll);
    }

    function getGasCompensation() external view returns (uint) {
        return GAS_COMPENSATION;
    }

    function getCompositeDebt(uint _debt) external view returns (uint) {
        return _getCompositeDebt(_debt);
    }

    function unprotectedDecayBaseRateFromBorrowing() external returns (uint) {
        baseRate = _calcDecayedBaseRate();
        assert(baseRate >= 0 && baseRate <= DECIMAL_PRECISION);

        _updateLastFeeOpTime();
        return baseRate;
    }

    function minutesPassedSinceLastFeeOp() external view returns (uint) {
        return _minutesPassedSinceLastFeeOp();
    }

    function setLastFeeOpTimeToNow() external {
        lastFeeOperationTime = block.timestamp;
    }

    function setBaseRate(uint _baseRate) external {
        baseRate = _baseRate;
    }

    function callGetRedemptionFee(uint _FILDrawn) external view returns (uint) {
        return _getRedemptionFee(_FILDrawn);
    }

    function getActualDebtFromComposite(uint _debtVal) external view returns (uint) {
        return _getNetDebt(_debtVal);
    }

    function callInternalRemoveTroveOwner(address _troveOwner) external {
        uint troveOwnersArrayLength = TroveOwners.length;
        _removeTroveOwner(_troveOwner, troveOwnersArrayLength);
    }

    function unprotectedRedistributeDebtAndColl(uint _debt, uint _coll) external {
        _redistributeDebtAndColl(activePool, defaultPool, _debt, _coll);
    }
}
