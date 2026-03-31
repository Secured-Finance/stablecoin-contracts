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
        MockAggregator mockPriceAggregator = MockAggregator(address(priceAggregator));

        mockPriceAggregator.setPrice(_price);
        mockPriceAggregator.setDecimals(18);
        mockPriceAggregator.setLatestRoundId(1);
        mockPriceAggregator.setUseBlockTimestamp(true);

        _changeStatus(Status.chainlinkWorking);
    }

    function setPriceAggregator(address _aggregator, int _price) external onlyOwner {
        priceAggregator = AggregatorV3Interface(_aggregator);
        setPrice(_price);
    }
}
