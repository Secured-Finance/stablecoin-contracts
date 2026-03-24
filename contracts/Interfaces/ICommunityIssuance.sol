// SPDX-License-Identifier: MIT

pragma solidity 0.7.6;

interface ICommunityIssuance {
    // --- Events ---

    event ProtocolTokenAddressChanged(address _protocolTokenAddress);
    event StabilityPoolAddressChanged(address _stabilityPoolAddress);
    event NewEmissionEpochStarted(
        uint _newProtocolTokenSupplyCap,
        uint _additionalAmount,
        uint _issuedOffset
    );
    event TotalProtocolTokenIssuedUpdated(uint _totalProtocolTokenIssued);
    event PendingProtocolTokenIssuanceUpdated(uint pendingProtocolTokenIssuance);

    // --- Functions ---

    function protocolTokenSupplyCap() external view returns (uint);

    function issueProtocolToken() external returns (uint);

    function sendProtocolToken(address _account, uint _amount) external;
}
