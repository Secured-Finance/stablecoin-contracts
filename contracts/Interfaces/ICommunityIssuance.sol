// SPDX-License-Identifier: MIT

pragma solidity 0.7.6;

interface ICommunityIssuance {
    // --- Events ---

    event ProtocolTokenAddressChanged(address _protocolTokenAddress);
    event StabilityPoolAddressChanged(address _stabilityPoolAddress);
    event ProtocolTokenSupplyCapIncreased(uint _newProtocolTokenSupplyCap, uint _increased);
    event TotalProtocolTokenIssuedUpdated(uint _totalProtocolTokenIssued);

    // --- Functions ---

    function protocolTokenSupplyCap() external view returns (uint);

    function issueProtocolToken() external returns (uint);

    function sendProtocolToken(address _account, uint _amount) external;
}
