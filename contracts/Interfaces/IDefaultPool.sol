// SPDX-License-Identifier: MIT

pragma solidity 0.7.6;

import "./IPool.sol";

interface IDefaultPool is IPool {
    // --- Events ---
    event TroveManagerAddressChanged(address _newTroveManagerAddress);
    event DefaultPoolDebtUpdated(uint _debt);
    event DefaultPoolFILBalanceUpdated(uint _FIL);

    // --- Functions ---
    function sendFILToActivePool(uint _amount) external;
}
