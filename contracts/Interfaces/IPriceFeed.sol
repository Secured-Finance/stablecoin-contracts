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

    // --- Function ---
    function fetchPrice() external returns (uint);

    function fetchPriceView() external returns (uint);
}
