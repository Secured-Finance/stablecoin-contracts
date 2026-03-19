// SPDX-License-Identifier: MIT

pragma solidity 0.7.6;
pragma abicoder v2;

import "./IPyth.sol";
import "./AggregatorV3Interface.sol";

/**
 * @title A Chainlink-based aggregator contract powered by pyth network feeds
 * @notice This contract always uses the price publish time as the round id,
 * as pyth network does not have a concept of rounds.
 */
contract PythCaller is AggregatorV3Interface {
    bytes32 public immutable priceId;
    IPyth public immutable pyth;
    string private _description;

    constructor(address pyth_, bytes32 priceId_, string memory description_) {
        priceId = priceId_;
        pyth = IPyth(pyth_);
        _description = description_;
    }

    function updateFeeds(bytes[] calldata priceUpdateData) public payable {
        // Update the prices to the latest available values and pay the required fee for it. The `priceUpdateData` data
        // should be retrieved from our off-chain Price Service API using the `pyth-evm-js` package.
        // See section "How Pyth Works on EVM Chains" below for more information.
        uint fee = pyth.getUpdateFee(priceUpdateData);
        pyth.updatePriceFeeds{value: fee}(priceUpdateData);

        // refund remaining eth
        (bool success, ) = payable(msg.sender).call{value: address(this).balance}("");
        require(success, "PythCaller: refund failed");
    }

    function decimals() public view override returns (uint8) {
        IPyth.Price memory price = pyth.getPriceUnsafe(priceId);
        require(price.expo < 0 && price.expo >= -18, "PythCaller: expo out of range");
        return uint8(-1 * int8(price.expo));
    }

    function description() external view override returns (string memory) {
        return _description;
    }

    function version() public pure override returns (uint256) {
        return 1;
    }

    function getRoundData(
        uint80 _roundId
    )
        external
        view
        override
        returns (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        )
    {
        IPyth.Price memory price = pyth.getPriceUnsafe(priceId);
        return (
            _roundId,
            int256(price.price),
            price.publishTime,
            price.publishTime,
            uint80(price.publishTime)
        );
    }

    function latestRoundData()
        external
        view
        override
        returns (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        )
    {
        IPyth.Price memory price = pyth.getPriceUnsafe(priceId);
        roundId = uint80(price.publishTime);
        return (roundId, int256(price.price), price.publishTime, price.publishTime, roundId);
    }
}
