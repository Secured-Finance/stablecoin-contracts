// SPDX-License-Identifier: MIT

pragma solidity 0.7.6;

import "../Dependencies/OpenZeppelin/interfaces/IERC2612.sol";
import "../Dependencies/OpenZeppelin/token/ERC20/extensions/IERC20Metadata.sol";
import "./IERC3009.sol";

interface IDebtToken is IERC20Metadata, IERC2612, IERC3009 {
    // --- Events ---

    event TroveManagerAddressChanged(address _troveManagerAddress);
    event StabilityPoolAddressChanged(address _newStabilityPoolAddress);
    event BorrowerOperationsAddressChanged(address _newBorrowerOperationsAddress);

    // --- Functions ---

    function mint(address _account, uint256 _amount) external;

    function burn(address _account, uint256 _amount) external;

    function sendToPool(address _sender, address poolAddress, uint256 _amount) external;

    function returnFromPool(address poolAddress, address user, uint256 _amount) external;
}
