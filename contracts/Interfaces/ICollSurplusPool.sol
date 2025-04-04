// SPDX-License-Identifier: MIT

pragma solidity 0.7.6;

interface ICollSurplusPool {
    // --- Events ---

    event CollSurplusPoolFILBalanceUpdated(uint _newBalance);
    event BorrowerOperationsAddressChanged(address _newBorrowerOperationsAddress);
    event TroveManagerAddressChanged(address _newTroveManagerAddress);
    event ActivePoolAddressChanged(address _newActivePoolAddress);

    event CollBalanceUpdated(address indexed _account, uint _newBalance);
    event FILSent(address _to, uint _amount);

    // --- Contract setters ---

    function getFIL() external view returns (uint);

    function getCollateral(address _account) external view returns (uint);

    function accountSurplus(address _account, uint _amount) external;

    function claimColl(address _account) external;
}
