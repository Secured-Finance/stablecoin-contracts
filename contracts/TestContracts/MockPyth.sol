// SPDX-License-Identifier: MIT

pragma solidity 0.7.6;
pragma abicoder v2;

import "../Dependencies/IPyth.sol";

contract MockPyth is IPyth {
    mapping(bytes32 => Price) private prices;
    uint private updateFee;

    function setPrice(bytes32 id, int64 price, uint64 conf, int32 expo, uint publishTime) external {
        prices[id] = Price({price: price, conf: conf, expo: expo, publishTime: publishTime});
    }

    function setUpdateFee(uint fee) external {
        updateFee = fee;
    }

    function getValidTimePeriod() external pure override returns (uint validTimePeriod) {
        return 300; // 5 minutes
    }

    function getPrice(bytes32 id) external view override returns (Price memory price) {
        return prices[id];
    }

    function getEmaPrice(bytes32 id) external view override returns (Price memory price) {
        return prices[id];
    }

    function getPriceUnsafe(bytes32 id) external view override returns (Price memory price) {
        return prices[id];
    }

    function getPriceNoOlderThan(
        bytes32 id,
        uint /*age*/
    ) external view override returns (Price memory price) {
        return prices[id];
    }

    function getEmaPriceUnsafe(bytes32 id) external view override returns (Price memory price) {
        return prices[id];
    }

    function getEmaPriceNoOlderThan(
        bytes32 id,
        uint /*age*/
    ) external view override returns (Price memory price) {
        return prices[id];
    }

    function updatePriceFeeds(bytes[] calldata /*updateData*/) external payable override {
        require(msg.value >= updateFee, "Insufficient fee");

        // Refund excess
        if (msg.value > updateFee) {
            (bool success, ) = payable(msg.sender).call{value: msg.value - updateFee}("");
            require(success, "Refund failed");
        }
    }

    function updatePriceFeedsIfNecessary(
        bytes[] calldata updateData,
        bytes32[] calldata /*priceIds*/,
        uint64[] calldata /*publishTimes*/
    ) external payable override {
        this.updatePriceFeeds{value: msg.value}(updateData);
    }

    function getUpdateFee(
        bytes[] calldata /*updateData*/
    ) external view override returns (uint feeAmount) {
        return updateFee;
    }

    function parsePriceFeedUpdates(
        bytes[] calldata /*updateData*/,
        bytes32[] calldata priceIds,
        uint64 /*minPublishTime*/,
        uint64 /*maxPublishTime*/
    ) external payable override returns (PriceFeed[] memory priceFeeds) {
        priceFeeds = new PriceFeed[](priceIds.length);
        for (uint i = 0; i < priceIds.length; i++) {
            priceFeeds[i] = PriceFeed({
                id: priceIds[i],
                price: prices[priceIds[i]],
                emaPrice: prices[priceIds[i]]
            });
        }
        return priceFeeds;
    }

    function parsePriceFeedUpdatesUnique(
        bytes[] calldata updateData,
        bytes32[] calldata priceIds,
        uint64 minPublishTime,
        uint64 maxPublishTime
    ) external payable override returns (PriceFeed[] memory priceFeeds) {
        return this.parsePriceFeedUpdates(updateData, priceIds, minPublishTime, maxPublishTime);
    }

    receive() external payable {}
}
