// SPDX-License-Identifier: MIT

pragma solidity 0.7.6;

interface ITellorCaller {
    function getTellorCurrentValue() external view returns (bool, uint256, uint256);
}
