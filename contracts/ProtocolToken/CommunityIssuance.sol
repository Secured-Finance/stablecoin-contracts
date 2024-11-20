// SPDX-License-Identifier: MIT

pragma solidity 0.7.6;

import "../Interfaces/IProtocolToken.sol";
import "../Interfaces/ICommunityIssuance.sol";
import "../Dependencies/OpenZeppelin/access/OwnableUpgradeable.sol";
import "../Dependencies/OpenZeppelin/math/SafeMath.sol";
import "../Dependencies/BaseMath.sol";
import "../Dependencies/ProtocolMath.sol";
import "../Dependencies/CheckContract.sol";

contract CommunityIssuance is ICommunityIssuance, OwnableUpgradeable, CheckContract, BaseMath {
    using SafeMath for uint;

    // --- Data ---

    string public constant NAME = "CommunityIssuance";

    uint public constant SECONDS_IN_ONE_MINUTE = 60;

    /* The issuance factor F determines the curvature of the issuance curve.
     *
     * Minutes in one year: 60*24*365 = 525600
     *
     * For 50% of remaining tokens issued each year, with minutes as time units, we have:
     *
     * F ** 525600 = 0.5
     *
     * Re-arranging:
     *
     * 525600 * ln(F) = ln(0.5)
     * F = 0.5 ** (1/525600)
     * F = 0.999998681227695000
     */
    uint public constant ISSUANCE_FACTOR = 999998681227695000;

    /*
     * The community ProtocolToken supply cap is the starting balance of the Community Issuance contract.
     * It should be minted to this contract by ProtocolToken, when the token is deployed.
     *
     * Set to 32M (slightly less than 1/3) of total ProtocolToken supply.
     */
    uint public override protocolTokenSupplyCap;

    IProtocolToken public protocolToken;

    address public stabilityPoolAddress;

    uint public totalProtocolTokenIssued;
    uint public supplyStartTime;

    // --- Functions ---

    function initialize(
        address _protocolTokenAddress,
        address _stabilityPoolAddress
    ) external initializer {
        __Ownable_init();
        _setAddresses(_protocolTokenAddress, _stabilityPoolAddress);

        protocolTokenSupplyCap = 0;
    }

    function _setAddresses(address _protocolTokenAddress, address _stabilityPoolAddress) private {
        checkContract(_protocolTokenAddress);
        checkContract(_stabilityPoolAddress);

        protocolToken = IProtocolToken(_protocolTokenAddress);
        stabilityPoolAddress = _stabilityPoolAddress;

        emit ProtocolTokenAddressSet(_protocolTokenAddress);
        emit StabilityPoolAddressSet(_stabilityPoolAddress);
    }

    function updateProtocolTokenSupplyCap() external onlyOwner {
        uint newProtocolTokenSupplyCap = protocolToken.balanceOf(address(this));

        require(
            newProtocolTokenSupplyCap != protocolTokenSupplyCap,
            "CommunityIssuance: supply cap not changed"
        );

        protocolTokenSupplyCap = newProtocolTokenSupplyCap;
        totalProtocolTokenIssued = 0;
        supplyStartTime = block.timestamp;

        emit ProtocolTokenSupplyCapUpdated(protocolTokenSupplyCap);
    }

    function issueProtocolToken() external override returns (uint) {
        _requireCallerIsStabilityPool();

        uint latestTotalProtocolTokenIssued = protocolTokenSupplyCap
            .mul(_getCumulativeIssuanceFraction())
            .div(DECIMAL_PRECISION);
        uint issuance = latestTotalProtocolTokenIssued.sub(totalProtocolTokenIssued);

        totalProtocolTokenIssued = latestTotalProtocolTokenIssued;
        emit TotalProtocolTokenIssuedUpdated(latestTotalProtocolTokenIssued);

        return issuance;
    }

    /* Gets 1-f^t    where: f < 1

    f: issuance factor that determines the shape of the curve
    t:  time passed since last ProtocolToken issuance event  */
    function _getCumulativeIssuanceFraction() internal view returns (uint) {
        // Get the time passed since deployment
        uint timePassedInMinutes = block.timestamp.sub(supplyStartTime).div(SECONDS_IN_ONE_MINUTE);

        // f^t
        uint power = ProtocolMath._decPow(ISSUANCE_FACTOR, timePassedInMinutes);

        //  (1 - f^t)
        uint cumulativeIssuanceFraction = (uint(DECIMAL_PRECISION).sub(power));
        assert(cumulativeIssuanceFraction <= DECIMAL_PRECISION); // must be in range [0,1]

        return cumulativeIssuanceFraction;
    }

    function sendProtocolToken(address _account, uint _amount) external override {
        _requireCallerIsStabilityPool();

        protocolToken.transfer(_account, _amount);
    }

    // --- 'require' functions ---

    function _requireCallerIsStabilityPool() internal view {
        require(msg.sender == stabilityPoolAddress, "CommunityIssuance: caller is not SP");
    }
}
