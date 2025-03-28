// SPDX-License-Identifier: MIT

pragma solidity 0.7.6;

contract FILTransferScript {
    function transferFIL(address _recipient, uint256 _amount) external returns (bool) {
        (bool success, ) = _recipient.call{value: _amount}("");
        return success;
    }
}
