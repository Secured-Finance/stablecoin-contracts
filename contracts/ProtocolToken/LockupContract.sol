// SPDX-License-Identifier: MIT

pragma solidity 0.7.6;

import "../Dependencies/OpenZeppelin/math/SafeMath.sol";
import "../Interfaces/IProtocolToken.sol";

/*
 * The lockup contract architecture utilizes a single LockupContract, with an unlockTime. The unlockTime is passed as an argument
 * to the LockupContract's constructor. The contract's balance can be withdrawn by the beneficiary when block.timestamp > unlockTime.
 * At construction, the contract checks that unlockTime is at least one year later than the protocol system's deployment time.
 *
 * The above two restrictions ensure that until one year after system deployment, ProtocolTokens originating from the deployer cannot
 * enter circulating supply and cannot be staked to earn system revenue.
 */
contract LockupContract {
    using SafeMath for uint;

    // --- Data ---
    string public constant NAME = "LockupContract";

    uint public constant SECONDS_IN_ONE_YEAR = 31536000;

    address public immutable beneficiary;

    IProtocolToken public immutable protocolToken;

    // Unlock time is the Unix point in time at which the beneficiary can withdraw.
    uint public immutable unlockTime;

    // --- Events ---

    event LockupContractCreated(address _beneficiary, uint _unlockTime);
    event LockupContractEmptied(uint _ProtocolTokenWithdrawal);

    // --- Functions ---

    constructor(address _protocolTokenAddress, address _beneficiary, uint _unlockTime) {
        /*
         * Set the unlock time to a chosen instant in the future, as long as it is at least 1 year after
         * the initial allocation start time.
         */
        _requireUnlockTimeIsAtLeastOneYearAfterAllocationStart(_protocolTokenAddress, _unlockTime);
        _requireBeneficiaryIsNonZero(_beneficiary);

        protocolToken = IProtocolToken(_protocolTokenAddress);
        unlockTime = _unlockTime;
        beneficiary = _beneficiary;

        emit LockupContractCreated(_beneficiary, _unlockTime);
    }

    function withdrawProtocolToken() external {
        _requireCallerIsBeneficiary();
        _requireLockupDurationHasPassed();

        IProtocolToken protocolTokenCached = protocolToken;
        uint protocolTokenBalance = protocolTokenCached.balanceOf(address(this));
        protocolTokenCached.transfer(beneficiary, protocolTokenBalance);
        emit LockupContractEmptied(protocolTokenBalance);
    }

    // --- 'require' functions ---

    function _requireCallerIsBeneficiary() internal view {
        require(msg.sender == beneficiary, "LockupContract: caller is not the beneficiary");
    }

    function _requireLockupDurationHasPassed() internal view {
        require(
            block.timestamp >= unlockTime,
            "LockupContract: The lockup duration must have passed"
        );
    }

    function _requireBeneficiaryIsNonZero(address _beneficiary) internal pure {
        require(_beneficiary != address(0), "LockupContract: beneficiary cannot be zero address");
    }

    function _requireUnlockTimeIsAtLeastOneYearAfterAllocationStart(
        address _protocolTokenAddress,
        uint _unlockTime
    ) internal view {
        uint tokenAllocationTime = IProtocolToken(_protocolTokenAddress).getAllocationStartTime();

        require(
            tokenAllocationTime != 0,
            "LockupContract: initial allocation has not been triggered"
        );
        require(
            _unlockTime >= tokenAllocationTime.add(SECONDS_IN_ONE_YEAR),
            "LockupContract: unlock time must be at least one year after allocation start"
        );
    }
}
