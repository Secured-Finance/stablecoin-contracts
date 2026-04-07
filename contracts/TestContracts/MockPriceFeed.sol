// SPDX-License-Identifier: MIT

pragma solidity 0.7.6;

import "../PriceFeed.sol";
import "../Dependencies/AggregatorV3Interface.sol";
import "./MockAggregator.sol";

contract MockPriceFeed is PriceFeed {
    constructor(
        uint _oracleTimeout,
        uint _lastGoodPriceTimeout
    ) PriceFeed(_oracleTimeout, _lastGoodPriceTimeout) {}

    function setPrice(int _price) public onlyOwner {
        MockAggregator(address(priceAggregator)).setPrice(_price);

        _changeStatus(Status.chainlinkWorking);
    }

    function setPriceAggregator(address _aggregator) external onlyOwner {
        priceAggregator = AggregatorV3Interface(_aggregator);
        MockAggregator mockPriceAggregator = MockAggregator(address(_aggregator));

        mockPriceAggregator.setDecimals(18);
        mockPriceAggregator.setLatestRoundId(1);
        mockPriceAggregator.setUseBlockTimestamp(true);
    }
}
