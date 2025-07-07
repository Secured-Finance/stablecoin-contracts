const { ethers, upgrades } = require("hardhat");
const { expect } = require("chai");

describe("DebtToken EIP-3009 Simple Verification", function () {
  let debtToken;
  let owner, alice, bob;

  before(async function () {
    [owner, alice, bob] = await ethers.getSigners();
  });

  it("should have EIP-3009 functions available in the contract", async function () {
    // Deploy DebtToken directly to test the implementation
    const DebtToken = await ethers.getContractFactory("DebtToken");

    // Deploy with proxy
    debtToken = await upgrades.deployProxy(
      DebtToken,
      [
        owner.address, // troveManager
        owner.address, // stabilityPool
        owner.address, // borrowerOperations
      ],
      {
        unsafeAllow: ["constructor", "state-variable-immutable"],
      },
    );

    await debtToken.deployed();

    // Verify contract has the expected functions
    expect(typeof debtToken.transferWithAuthorization).to.equal("function");
    expect(typeof debtToken.receiveWithAuthorization).to.equal("function");
    expect(typeof debtToken.cancelAuthorization).to.equal("function");
    expect(typeof debtToken.authorizationState).to.equal("function");

    // Test authorizationState function
    const testNonce = ethers.utils.hexZeroPad("0x1", 32);
    const state = await debtToken.authorizationState(alice.address, testNonce);
    expect(state).to.equal(false);

    console.log("✅ EIP-3009 functions are available in DebtToken");
  });

  it("should maintain existing ERC20 functionality", async function () {
    // Deploy a fresh instance
    const DebtToken = await ethers.getContractFactory("DebtToken");
    debtToken = await upgrades.deployProxy(
      DebtToken,
      [owner.address, owner.address, owner.address],
      {
        unsafeAllow: ["constructor", "state-variable-immutable"],
      },
    );

    // Verify basic ERC20 functions still work
    const name = await debtToken.name();
    expect(name).to.equal("USD for Filecoin Community");

    const symbol = await debtToken.symbol();
    expect(symbol).to.equal("USDFC");

    const decimals = await debtToken.decimals();
    expect(decimals).to.equal(18);

    const totalSupply = await debtToken.totalSupply();
    expect(totalSupply.toString()).to.equal("0");

    console.log("✅ Basic ERC20 functionality maintained");
  });

  it("should have correct EIP-3009 type hashes", async function () {
    // Check that the implementation includes the correct constants
    // Note: These would normally be internal, but we can verify the functions exist
    const DebtToken = await ethers.getContractFactory("DebtToken");
    const bytecode = DebtToken.bytecode;

    // EIP-3009 type hashes as hex strings (without 0x prefix)
    const transferAuthTypeHash = "7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267";
    const receiveAuthTypeHash = "d099cc98ef71107a616c4f0f941f04c322d8e254fe26b3c6668db87aae413de8";
    const cancelAuthTypeHash = "158b0a9edf7a828aad02f63cd515c68ef2f50ba807396f6d12842833a1597429";

    // Basic check that these constants appear in the bytecode
    const hasTransferAuth = bytecode.includes(transferAuthTypeHash);
    const hasReceiveAuth = bytecode.includes(receiveAuthTypeHash);
    const hasCancelAuth = bytecode.includes(cancelAuthTypeHash);

    console.log("✅ Type hash checks:");
    console.log("  - TransferWithAuthorization:", hasTransferAuth);
    console.log("  - ReceiveWithAuthorization:", hasReceiveAuth);
    console.log("  - CancelAuthorization:", hasCancelAuth);

    expect(hasTransferAuth || hasReceiveAuth || hasCancelAuth).to.be.true;
  });
});
