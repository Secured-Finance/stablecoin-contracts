// SPDX-License-Identifier: MIT

pragma solidity 0.7.6;

import "./Interfaces/IPriceFeed.sol";
import "./Interfaces/ITellorCaller.sol";
import "./Dependencies/OpenZeppelin/access/OwnableUpgradeable.sol";
import "./Dependencies/OpenZeppelin/math/SafeMath.sol";
import "./Dependencies/AggregatorV3Interface.sol";
import "./Dependencies/CheckContract.sol";
import "./Dependencies/BaseMath.sol";
import "./Dependencies/ProtocolMath.sol";

/*
 * PriceFeed for mainnet deployment, to be connected to Pyth's live aggregator reference contract,
 * and a wrapper contract TellorCaller, which connects to TellorMaster contract.
 *
 * The PriceFeed uses Pyth as primary oracle, and Tellor as fallback. It contains logic for
 * switching oracles based on oracle failures, timeouts, and conditions for returning to the primary
 * Pyth oracle.
 */
contract PriceFeed is OwnableUpgradeable, CheckContract, BaseMath, IPriceFeed {
    using SafeMath for uint256;

    string public constant NAME = "PriceFeed";

    AggregatorV3Interface public priceAggregator;
    ITellorCaller public tellorCaller; // Wrapper contract that calls the Tellor system

    // Use to convert a price answer to an 18-digit precision uint
    uint public constant TARGET_DIGITS = 18;

    // Maximum time period allowed since oracle's latest data timestamp, beyond which the oracle is considered frozen.
    uint public immutable ORACLE_TIMEOUT;

    // Maximum time period allowed since lastGoodPrice was updated, beyond which lastGoodPrice is considered too old.
    // This should be longer than ORACLE_TIMEOUT to allow lastGoodPrice to remain valid when oracles are temporarily unavailable.
    uint public immutable LAST_GOOD_PRICE_TIMEOUT;

    // Maximum deviation allowed between two consecutive Chainlink oracle prices. 18-digit precision.
    uint public constant MAX_PRICE_DEVIATION_FROM_PREVIOUS_ROUND = 5e17; // 50%

    /*
     * The maximum relative price difference between two oracle responses allowed in order for the PriceFeed
     * to return to using the Chainlink oracle. 18-digit precision.
     */
    uint public constant MAX_PRICE_DIFFERENCE_BETWEEN_ORACLES = 5e16; // 5%

    // The last good price seen from an oracle by the PriceFeed contract
    uint public lastGoodPrice;

    struct ChainlinkResponse {
        uint80 roundId;
        int256 answer;
        uint256 timestamp;
        bool success;
        uint8 decimals;
    }

    struct TellorResponse {
        bool ifRetrieve;
        uint256 value;
        uint256 timestamp;
        bool success;
    }

    // The current status of the PricFeed, which determines the conditions for the next price fetch attempt
    Status public status;

    // The timestamp when the last good price was stored
    uint public lastGoodPriceTimestamp;

    constructor(uint _oracleTimeout, uint _lastGoodPriceTimeout) initializer {
        require(
            _lastGoodPriceTimeout >= _oracleTimeout,
            "PriceFeed: LAST_GOOD_PRICE_TIMEOUT must be greater than or equal to ORACLE_TIMEOUT"
        );

        ORACLE_TIMEOUT = _oracleTimeout;
        LAST_GOOD_PRICE_TIMEOUT = _lastGoodPriceTimeout;
    }

    // --- Dependency setters ---

    function initialize(
        address _priceAggregatorAddress,
        address _tellorCallerAddress
    ) external initializer {
        __Ownable_init();
        _setAddresses(_priceAggregatorAddress, _tellorCallerAddress);
    }

    function _setAddresses(address _priceAggregatorAddress, address _tellorCallerAddress) private {
        checkContract(_priceAggregatorAddress);
        checkContract(_tellorCallerAddress);

        priceAggregator = AggregatorV3Interface(_priceAggregatorAddress);
        tellorCaller = ITellorCaller(_tellorCallerAddress);

        // Explicitly set initial system status
        status = Status.chainlinkWorking;

        // Get an initial price from Chainlink to serve as first reference for lastGoodPrice
        ChainlinkResponse memory chainlinkResponse = _getCurrentChainlinkResponse();

        require(
            !_chainlinkIsBroken(chainlinkResponse) && !_chainlinkIsFrozen(chainlinkResponse),
            "PriceFeed: Chainlink must be working and current"
        );

        _storeChainlinkPrice(chainlinkResponse);
    }

    // --- Functions ---

    /*
     * fetchPrice():
     * Returns the latest price obtained from the Oracle. Called by protocol functions that require a current price.
     *
     * Also callable by anyone externally.
     *
     * Non-view function - it stores the last good price seen by the PriceFeed contract.
     *
     * Uses a main oracle (Chainlink) and a fallback oracle (Tellor) in case Chainlink fails. If both fail,
     * it uses the last good price seen by the PriceFeed contract.
     *
     */
    function fetchPrice() external override returns (uint price) {
        // Get current and previous price data from Chainlink, and current price data from Tellor
        ChainlinkResponse memory chainlinkResponse = _getCurrentChainlinkResponse();
        TellorResponse memory tellorResponse = _getCurrentTellorResponse();

        // --- CASE 1: System fetched last price from Chainlink  ---
        if (status == Status.chainlinkWorking) {
            // If Chainlink is broken, try Tellor
            if (_chainlinkIsBroken(chainlinkResponse)) {
                // If Tellor is broken then both oracles are untrusted, so return the last good price
                if (_tellorIsBroken(tellorResponse)) {
                    _changeStatus(Status.bothOraclesUntrusted);
                    return _getLastGoodPrice();
                }
                /*
                 * If Tellor is only frozen but otherwise returning valid data, return the last good price.
                 * Tellor may need to be tipped to return current data.
                 */
                if (_tellorIsFrozen(tellorResponse)) {
                    _changeStatus(Status.usingTellorChainlinkUntrusted);
                    return _getLastGoodPrice();
                }

                // If Chainlink is broken and Tellor is working, switch to Tellor and return current Tellor price
                _changeStatus(Status.usingTellorChainlinkUntrusted);
                return _storeTellorPrice(tellorResponse);
            }

            // If Chainlink is frozen, try Tellor
            if (_chainlinkIsFrozen(chainlinkResponse)) {
                // If Tellor is broken too, remember Tellor broke, and return last good price
                if (_tellorIsBroken(tellorResponse)) {
                    _changeStatus(Status.usingChainlinkTellorUntrusted);
                    return _getLastGoodPrice();
                }

                // If Tellor is frozen or working, remember Chainlink froze, and switch to Tellor
                _changeStatus(Status.usingTellorChainlinkFrozen);

                if (_tellorIsFrozen(tellorResponse)) {
                    return _getLastGoodPrice();
                }

                // If Tellor is working, use it
                return _storeTellorPrice(tellorResponse);
            }

            // If Chainlink price has changed by > 50% between the latest round and the last good price, compare it to Tellor's price
            if (_chainlinkPriceChangeAboveMax(chainlinkResponse)) {
                // If Tellor is broken, both oracles are untrusted, and return last good price
                if (_tellorIsBroken(tellorResponse)) {
                    _changeStatus(Status.bothOraclesUntrusted);
                    return _getLastGoodPrice();
                }

                // If Tellor is frozen, switch to Tellor and return last good price
                if (_tellorIsFrozen(tellorResponse)) {
                    _changeStatus(Status.usingTellorChainlinkUntrusted);
                    return _getLastGoodPrice();
                }

                /*
                 * If Tellor is live and both oracles have a similar price, conclude that Chainlink's large price deviation between
                 * two consecutive rounds was likely a legitmate market price movement, and so continue using Chainlink
                 */
                if (_bothOraclesSimilarPrice(chainlinkResponse, tellorResponse)) {
                    return _storeChainlinkPrice(chainlinkResponse);
                }

                // If Tellor is live but the oracles differ too much in price, conclude that Chainlink's initial price deviation was
                // an oracle failure. Switch to Tellor, and use Tellor price
                _changeStatus(Status.usingTellorChainlinkUntrusted);
                return _storeTellorPrice(tellorResponse);
            }

            // If Chainlink is working and Tellor is broken, remember Tellor is broken
            if (_tellorIsBroken(tellorResponse)) {
                _changeStatus(Status.usingChainlinkTellorUntrusted);
            }

            // If Chainlink is working, return Chainlink current price (no status change)
            return _storeChainlinkPrice(chainlinkResponse);
        }

        // --- CASE 2: The system fetched last price from Tellor ---
        if (status == Status.usingTellorChainlinkUntrusted) {
            // If both Tellor and Chainlink are live, unbroken, and reporting similar prices, switch back to Chainlink
            if (_bothOraclesLiveAndUnbrokenAndSimilarPrice(chainlinkResponse, tellorResponse)) {
                _changeStatus(Status.chainlinkWorking);
                return _storeChainlinkPrice(chainlinkResponse);
            }

            if (_tellorIsBroken(tellorResponse)) {
                _changeStatus(Status.bothOraclesUntrusted);
                return _getLastGoodPrice();
            }

            /*
             * If Tellor is only frozen but otherwise returning valid data, just return the last good price.
             * Tellor may need to be tipped to return current data.
             */
            if (_tellorIsFrozen(tellorResponse)) {
                return _getLastGoodPrice();
            }

            // Otherwise, use Tellor price
            return _storeTellorPrice(tellorResponse);
        }

        // --- CASE 3: Both oracles were untrusted at the last price fetch ---
        if (status == Status.bothOraclesUntrusted) {
            /*
             * If both oracles are now live, unbroken and similar price, we assume that they are reporting
             * accurately, and so we switch back to Chainlink.
             */
            if (_bothOraclesLiveAndUnbrokenAndSimilarPrice(chainlinkResponse, tellorResponse)) {
                _changeStatus(Status.chainlinkWorking);
                return _storeChainlinkPrice(chainlinkResponse);
            }

            // Otherwise, return the last good price - both oracles are still untrusted (no status change)
            return _getLastGoodPrice();
        }

        // --- CASE 4: Using Tellor, and Chainlink is frozen ---
        if (status == Status.usingTellorChainlinkFrozen) {
            if (_chainlinkIsBroken(chainlinkResponse)) {
                // If both Oracles are broken, return last good price
                if (_tellorIsBroken(tellorResponse)) {
                    _changeStatus(Status.bothOraclesUntrusted);
                    return _getLastGoodPrice();
                }

                // If Chainlink is broken, remember it and switch to using Tellor
                _changeStatus(Status.usingTellorChainlinkUntrusted);

                if (_tellorIsFrozen(tellorResponse)) {
                    return _getLastGoodPrice();
                }

                // If Tellor is working, return Tellor current price
                return _storeTellorPrice(tellorResponse);
            }

            if (_chainlinkIsFrozen(chainlinkResponse)) {
                // if Chainlink is frozen and Tellor is broken, remember Tellor broke, and return last good price
                if (_tellorIsBroken(tellorResponse)) {
                    _changeStatus(Status.usingChainlinkTellorUntrusted);
                    return _getLastGoodPrice();
                }

                // If both are frozen, just use lastGoodPrice
                if (_tellorIsFrozen(tellorResponse)) {
                    return _getLastGoodPrice();
                }

                // if Chainlink is frozen and Tellor is working, keep using Tellor (no status change)
                return _storeTellorPrice(tellorResponse);
            }

            // if Chainlink is live and Tellor is broken, remember Tellor broke, and return Chainlink price
            if (_tellorIsBroken(tellorResponse)) {
                _changeStatus(Status.usingChainlinkTellorUntrusted);
                return _storeChainlinkPrice(chainlinkResponse);
            }

            // If Chainlink is live and Tellor is frozen, just use last good price (no status change) since we have no basis for comparison
            if (_tellorIsFrozen(tellorResponse)) {
                return _getLastGoodPrice();
            }

            // If Chainlink is live and Tellor is working, compare prices. Switch to Chainlink
            // if prices are within 5%, and return Chainlink price.
            if (_bothOraclesSimilarPrice(chainlinkResponse, tellorResponse)) {
                _changeStatus(Status.chainlinkWorking);
                return _storeChainlinkPrice(chainlinkResponse);
            }

            // Otherwise if Chainlink is live but price not within 5% of Tellor, distrust Chainlink, and return Tellor price
            _changeStatus(Status.usingTellorChainlinkUntrusted);
            return _storeTellorPrice(tellorResponse);
        }

        // --- CASE 5: Using Chainlink, Tellor is untrusted ---
        if (status == Status.usingChainlinkTellorUntrusted) {
            // If Chainlink breaks, now both oracles are untrusted
            if (_chainlinkIsBroken(chainlinkResponse)) {
                _changeStatus(Status.bothOraclesUntrusted);
                return _getLastGoodPrice();
            }

            // If Chainlink is frozen, return last good price (no status change)
            if (_chainlinkIsFrozen(chainlinkResponse)) {
                return _getLastGoodPrice();
            }

            // If Chainlink and Tellor are both live, unbroken and similar price, switch back to chainlinkWorking and return Chainlink price
            if (_bothOraclesLiveAndUnbrokenAndSimilarPrice(chainlinkResponse, tellorResponse)) {
                _changeStatus(Status.chainlinkWorking);
                return _storeChainlinkPrice(chainlinkResponse);
            }

            // If Chainlink is live but deviated >50% from the last good price and Tellor is still untrusted,
            // switch to bothOraclesUntrusted and return the last good price
            if (_chainlinkPriceChangeAboveMax(chainlinkResponse)) {
                _changeStatus(Status.bothOraclesUntrusted);
                return _getLastGoodPrice();
            }

            // Otherwise if Chainlink is live and deviated <50% from it's previous price and Tellor is still untrusted,
            // return Chainlink price (no status change)
            return _storeChainlinkPrice(chainlinkResponse);
        }
    }

    // --- Helper functions ---
    function _chainlinkIsBroken(ChainlinkResponse memory _response) internal view returns (bool) {
        // Check for response call reverted
        if (!_response.success) {
            return true;
        }
        // Check for an invalid roundId that is 0
        if (_response.roundId == 0) {
            return true;
        }
        // Check for an invalid timeStamp that is 0, or in the future
        if (_response.timestamp == 0 || _response.timestamp > block.timestamp) {
            return true;
        }
        // Check for non-positive price
        if (_response.answer <= 0) {
            return true;
        }

        return false;
    }

    function _chainlinkIsFrozen(ChainlinkResponse memory _response) internal view returns (bool) {
        return block.timestamp.sub(_response.timestamp) > ORACLE_TIMEOUT;
    }

    function _chainlinkPriceChangeAboveMax(
        ChainlinkResponse memory _response
    ) internal view returns (bool) {
        uint currentScaledPrice = _scaleChainlinkPriceByDigits(
            uint256(_response.answer),
            _response.decimals
        );

        uint minPrice = ProtocolMath._min(currentScaledPrice, lastGoodPrice);
        uint maxPrice = ProtocolMath._max(currentScaledPrice, lastGoodPrice);

        /*
         * Use the larger price as the denominator:
         * - If price decreased, the percentage deviation is in relation to the the previous price.
         * - If price increased, the percentage deviation is in relation to the current price.
         */
        uint percentDeviation = maxPrice.sub(minPrice).mul(DECIMAL_PRECISION).div(maxPrice);

        // Return true if price has more than doubled, or more than halved.
        return percentDeviation > MAX_PRICE_DEVIATION_FROM_PREVIOUS_ROUND;
    }

    function _tellorIsBroken(TellorResponse memory _response) internal view returns (bool) {
        // Check for response call reverted
        if (!_response.success) {
            return true;
        }
        // Check for an invalid timeStamp that is 0, or in the future
        if (_response.timestamp == 0 || _response.timestamp > block.timestamp) {
            return true;
        }
        // Check for zero price
        if (_response.value == 0) {
            return true;
        }

        return false;
    }

    function _tellorIsFrozen(TellorResponse memory _tellorResponse) internal view returns (bool) {
        return block.timestamp.sub(_tellorResponse.timestamp) > ORACLE_TIMEOUT;
    }

    function _lastGoodPriceIsFrozen() internal view returns (bool) {
        return block.timestamp.sub(lastGoodPriceTimestamp) > LAST_GOOD_PRICE_TIMEOUT;
    }

    function _getLastGoodPrice() internal view returns (uint) {
        require(!_lastGoodPriceIsFrozen(), "PriceFeed: lastGoodPrice is too old");
        return lastGoodPrice;
    }

    function _bothOraclesLiveAndUnbrokenAndSimilarPrice(
        ChainlinkResponse memory _chainlinkResponse,
        TellorResponse memory _tellorResponse
    ) internal view returns (bool) {
        // Return false if either oracle is broken or frozen
        if (
            _tellorIsBroken(_tellorResponse) ||
            _tellorIsFrozen(_tellorResponse) ||
            _chainlinkIsBroken(_chainlinkResponse) ||
            _chainlinkIsFrozen(_chainlinkResponse)
        ) {
            return false;
        }

        return _bothOraclesSimilarPrice(_chainlinkResponse, _tellorResponse);
    }

    function _bothOraclesSimilarPrice(
        ChainlinkResponse memory _chainlinkResponse,
        TellorResponse memory _tellorResponse
    ) internal pure returns (bool) {
        uint scaledChainlinkPrice = _scaleChainlinkPriceByDigits(
            uint256(_chainlinkResponse.answer),
            _chainlinkResponse.decimals
        );
        // No need to scale Tellor price, as it is already in 18-digit precision
        uint tellorPrice = _tellorResponse.value;

        // Get the relative price difference between the oracles. Use the lower price as the denominator, i.e. the reference for the calculation.
        uint minPrice = ProtocolMath._min(tellorPrice, scaledChainlinkPrice);
        uint maxPrice = ProtocolMath._max(tellorPrice, scaledChainlinkPrice);
        uint percentPriceDifference = maxPrice.sub(minPrice).mul(DECIMAL_PRECISION).div(minPrice);

        /*
         * Return true if the relative price difference is <= 5%: if so, we assume both oracles are probably reporting
         * the honest market price, as it is unlikely that both have been broken/hacked and are still in-sync.
         */
        return percentPriceDifference <= MAX_PRICE_DIFFERENCE_BETWEEN_ORACLES;
    }

    function _scaleChainlinkPriceByDigits(
        uint _price,
        uint _answerDigits
    ) internal pure returns (uint) {
        /*
         * Convert the price returned by the Chainlink oracle to an 18-digit decimal for use by the PriceFeed contract.
         * At date of protocol launch, Chainlink uses an 8-digit price, but we also handle the possibility of
         * future changes.
         *
         */
        uint price;
        if (_answerDigits >= TARGET_DIGITS) {
            // Scale the returned price value down to the protocol's target precision
            price = _price.div(10 ** (_answerDigits - TARGET_DIGITS));
        } else if (_answerDigits < TARGET_DIGITS) {
            // Scale the returned price value up to the protocol's target precision
            price = _price.mul(10 ** (TARGET_DIGITS - _answerDigits));
        }
        return price;
    }

    function _changeStatus(Status _status) internal {
        status = _status;
        emit PriceFeedStatusChanged(_status);
    }

    function _storePrice(uint _currentPrice) internal {
        lastGoodPrice = _currentPrice;
        lastGoodPriceTimestamp = block.timestamp;
        emit LastGoodPriceUpdated(_currentPrice);
    }

    function _storeTellorPrice(TellorResponse memory _tellorResponse) internal returns (uint) {
        // No need to scale Tellor price, as it is already in 18-digit precision
        uint tellorPrice = _tellorResponse.value;
        _storePrice(tellorPrice);

        return tellorPrice;
    }

    function _storeChainlinkPrice(
        ChainlinkResponse memory _chainlinkResponse
    ) internal returns (uint) {
        uint scaledChainlinkPrice = _scaleChainlinkPriceByDigits(
            uint256(_chainlinkResponse.answer),
            _chainlinkResponse.decimals
        );
        _storePrice(scaledChainlinkPrice);

        return scaledChainlinkPrice;
    }

    // --- Oracle response wrapper functions ---

    function _getCurrentTellorResponse() internal returns (TellorResponse memory tellorResponse) {
        try tellorCaller.getTellorCurrentValue() returns (
            bool ifRetrieve,
            uint256 value,
            uint256 _timestampRetrieved
        ) {
            // If call to Tellor succeeds, return the response and success = true
            tellorResponse.ifRetrieve = ifRetrieve;
            tellorResponse.value = value;
            tellorResponse.timestamp = _timestampRetrieved;
            tellorResponse.success = true;

            return (tellorResponse);
        } catch {
            // If call to Tellor reverts, return a zero response with success = false
            return (tellorResponse);
        }
    }

    function _getCurrentChainlinkResponse()
        internal
        view
        returns (ChainlinkResponse memory chainlinkResponse)
    {
        // First, try to get current decimal precision:
        try priceAggregator.decimals() returns (uint8 decimals) {
            // If call to Chainlink succeeds, record the current decimal precision
            chainlinkResponse.decimals = decimals;
        } catch {
            // If call to Chainlink aggregator reverts, return a zero response with success = false
            return chainlinkResponse;
        }

        // Secondly, try to get latest price data:
        try priceAggregator.latestRoundData() returns (
            uint80 roundId,
            int256 answer,
            uint256 /* startedAt */,
            uint256 timestamp,
            uint80 /* answeredInRound */
        ) {
            // If call to Chainlink succeeds, return the response and success = true
            chainlinkResponse.roundId = roundId;
            chainlinkResponse.answer = answer;
            chainlinkResponse.timestamp = timestamp;
            chainlinkResponse.success = true;
            return chainlinkResponse;
        } catch {
            // If call to Chainlink aggregator reverts, return a zero response with success = false
            return chainlinkResponse;
        }
    }
}
