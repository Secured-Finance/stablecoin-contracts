// SPDX-License-Identifier: MIT

pragma solidity 0.7.6;

import "../PriceFeed.sol";

contract PriceFeedTester is PriceFeed {
    constructor(
        uint _oracleTimeout,
        uint _lastGoodPriceTimeout
    ) PriceFeed(_oracleTimeout, _lastGoodPriceTimeout) {}

    function setLastGoodPrice(uint _lastGoodPrice) external {
        lastGoodPrice = _lastGoodPrice;
    }

    function setStatus(Status _status) external {
        status = _status;
    }
}
