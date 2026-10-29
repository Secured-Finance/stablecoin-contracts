// SPDX-License-Identifier: MIT

pragma solidity 0.7.6;

interface IPriceFeed {
    // --- Events ---
    event LastGoodPriceUpdated(uint _lastGoodPrice);
    event PriceFeedStatusChanged(Status newStatus);

    enum Status {
        chainlinkWorking,
        usingTellorChainlinkUntrusted,
        bothOraclesUntrusted,
        usingTellorChainlinkFrozen,
        usingChainlinkTellorUntrusted
    }

    enum PriceSource {
        primaryOracle,
        fallbackOracle,
        lastGoodPrice
    }

    // --- Function ---
    function fetchPrice() external returns (uint);

    function fetchPriceWithSource() external returns (uint, PriceSource);

    function fetchPriceView() external returns (uint);

    function fetchPriceWithSourceView() external returns (uint, PriceSource);
}
