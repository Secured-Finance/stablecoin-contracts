const deploymentHelper = require("../utils/testDeploymentHelpers.js");
const testHelpers = require("../utils/testHelpers.js");
const { accountsList } = require("../accountsList.js");

const { keccak256 } = require("@ethersproject/keccak256");
const { defaultAbiCoder } = require("@ethersproject/abi");
const { toUtf8Bytes } = require("@ethersproject/strings");
const { pack } = require("@ethersproject/solidity");
const { hexlify } = require("@ethersproject/bytes");
const { ecsign } = require("ethereumjs-util");
const { randomBytes } = require("@ethersproject/random");

const { toBN, assertRevert, dec, ZERO_ADDRESS, GAS_COMPENSATION, MIN_NET_DEBT } =
  testHelpers.TestHelper;

const sign = (digest, privateKey) => {
  return ecsign(Buffer.from(digest.slice(2), "hex"), Buffer.from(privateKey.slice(2), "hex"));
};

// EIP-3009 type hashes
const TRANSFER_WITH_AUTHORIZATION_TYPEHASH = keccak256(
  toUtf8Bytes(
    "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)",
  ),
);

// Gets the EIP712 domain separator
const getDomainSeparator = (name, contractAddress, chainId, version) => {
  return keccak256(
    defaultAbiCoder.encode(
      ["bytes32", "bytes32", "bytes32", "uint256", "address"],
      [
        keccak256(
          toUtf8Bytes(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
          ),
        ),
        keccak256(toUtf8Bytes(name)),
        keccak256(toUtf8Bytes(version)),
        parseInt(chainId),
        contractAddress.toLowerCase(),
      ],
    ),
  );
};

// Returns the EIP712 hash for transferWithAuthorization
const getTransferWithAuthorizationDigest = (
  name,
  address,
  chainId,
  version,
  from,
  to,
  value,
  validAfter,
  validBefore,
  nonce,
) => {
  const DOMAIN_SEPARATOR = getDomainSeparator(name, address, chainId, version);
  return keccak256(
    pack(
      ["bytes1", "bytes1", "bytes32", "bytes32"],
      [
        "0x19",
        "0x01",
        DOMAIN_SEPARATOR,
        keccak256(
          defaultAbiCoder.encode(
            ["bytes32", "address", "address", "uint256", "uint256", "uint256", "bytes32"],
            [TRANSFER_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce],
          ),
        ),
      ],
    ),
  );
};

contract("DebtToken - EIP3009 Integration Tests", async () => {
  let signers;
  let owner, alice, bob, carol, defaulter_1, defaulter_2;

  const alicePrivateKey = accountsList[1].privateKey;
  const bobPrivateKey = accountsList[2].privateKey;

  let chainId;
  let debtToken;
  let stabilityPool;
  let troveManager;
  let borrowerOperations;
  let activePool;
  let priceFeed;
  let hintHelpers;
  let sortedTroves;

  let contracts;

  let tokenName;
  let tokenVersion;

  const openTrove = async (signer, params = {}) => {
    return contracts.borrowerOperations
      .connect(signer)
      .openTrove(
        params.maxFeePercentage || toBN(dec(5, 16)),
        params.debtAmount || MIN_NET_DEBT,
        params.upperHint || ZERO_ADDRESS,
        params.lowerHint || ZERO_ADDRESS,
        { value: params.collAmount || dec(100, "ether") },
      );
  };

  const getTroveEntireColl = async (user) => troveManager.getTroveEntireColl(user);
  const getTroveEntireDebt = async (user) => troveManager.getTroveEntireDebt(user);

  before(async () => {
    signers = await ethers.getSigners();
    [owner, alice, bob, carol, defaulter_1, defaulter_2] = await signers.splice(0, 6);

    const transactionCount = await owner.getTransactionCount();
    const cpContracts = await deploymentHelper.computeCoreProtocolContracts(
      owner.address,
      transactionCount,
    );

    contracts = await deploymentHelper.deployProtocolCore(
      GAS_COMPENSATION,
      MIN_NET_DEBT,
      cpContracts,
    );

    debtToken = contracts.debtToken;
    stabilityPool = contracts.stabilityPool;
    troveManager = contracts.troveManager;
    borrowerOperations = contracts.borrowerOperations;
    activePool = contracts.activePool;
    priceFeed = contracts.priceFeedTestnet;
    hintHelpers = contracts.hintHelpers;
    sortedTroves = contracts.sortedTroves;

    // Set price to $100
    await priceFeed.setPrice(dec(100, 18));

    tokenName = await debtToken.name();
    tokenVersion = await debtToken.version();
    chainId = (await ethers.provider.getNetwork()).chainId;
  });

  describe("Integration with Stability Pool", () => {
    beforeEach(async () => {
      // Reset state
      await hre.network.provider.send("hardhat_reset");

      // Redeploy
      const transactionCount = await owner.getTransactionCount();
      const cpContracts = await deploymentHelper.computeCoreProtocolContracts(
        owner.address,
        transactionCount,
      );

      contracts = await deploymentHelper.deployProtocolCore(
        GAS_COMPENSATION,
        MIN_NET_DEBT,
        cpContracts,
      );

      debtToken = contracts.debtToken;
      stabilityPool = contracts.stabilityPool;
      troveManager = contracts.troveManager;
      borrowerOperations = contracts.borrowerOperations;
      activePool = contracts.activePool;
      priceFeed = contracts.priceFeedTestnet;
      sortedTroves = contracts.sortedTroves;

      await priceFeed.setPrice(dec(100, 18));

      tokenName = await debtToken.name();
      tokenVersion = await debtToken.version();

      // Setup: Alice and Bob open troves
      await openTrove(alice, { collAmount: dec(100, "ether"), debtAmount: dec(10000, 18) });
      await openTrove(bob, { collAmount: dec(100, "ether"), debtAmount: dec(5000, 18) });
    });

    it("should allow gasless deposit to stability pool via transferWithAuthorization", async () => {
      const depositAmount = toBN(dec(1000, 18));

      // Alice signs authorization to transfer to Bob
      const from = alice.address;
      const to = bob.address;
      const value = depositAmount;
      const validAfter = 0;
      const validBefore = Math.floor(Date.now() / 1000) + 3600;
      const nonce = randomBytes(32);

      const digest = getTransferWithAuthorizationDigest(
        tokenName,
        debtToken.address,
        chainId,
        tokenVersion,
        from,
        to,
        value,
        validAfter,
        validBefore,
        nonce,
      );

      const { v, r, s } = sign(digest, alicePrivateKey);

      // Bob receives tokens via gasless transfer
      await debtToken
        .connect(bob)
        .receiveWithAuthorization(
          from,
          to,
          value,
          validAfter,
          validBefore,
          nonce,
          v,
          hexlify(r),
          hexlify(s),
        );

      // Bob deposits to stability pool
      await stabilityPool.connect(bob).provideToSP(depositAmount, ZERO_ADDRESS);

      const bobDeposit = await stabilityPool.getCompoundedDebtTokenDeposits(bob.address);
      assert.isTrue(bobDeposit.eq(depositAmount));
    });

    it("should prevent transfers to stability pool via EIP-3009", async () => {
      const from = alice.address;
      const to = stabilityPool.address; // Invalid recipient
      const value = toBN(dec(1000, 18));
      const validAfter = 0;
      const validBefore = Math.floor(Date.now() / 1000) + 3600;
      const nonce = randomBytes(32);

      const digest = getTransferWithAuthorizationDigest(
        tokenName,
        debtToken.address,
        chainId,
        tokenVersion,
        from,
        to,
        value,
        validAfter,
        validBefore,
        nonce,
      );

      const { v, r, s } = sign(digest, alicePrivateKey);

      await assertRevert(
        debtToken.transferWithAuthorization(
          from,
          to,
          value,
          validAfter,
          validBefore,
          nonce,
          v,
          hexlify(r),
          hexlify(s),
        ),
        "DebtToken: Cannot transfer tokens directly to the StabilityPool, TroveManager or BorrowerOps",
      );
    });
  });

  describe("Integration with Trove Operations", () => {
    beforeEach(async () => {
      // Reset state
      await hre.network.provider.send("hardhat_reset");

      // Redeploy
      const transactionCount = await owner.getTransactionCount();
      const cpContracts = await deploymentHelper.computeCoreProtocolContracts(
        owner.address,
        transactionCount,
      );

      contracts = await deploymentHelper.deployProtocolCore(
        GAS_COMPENSATION,
        MIN_NET_DEBT,
        cpContracts,
      );

      debtToken = contracts.debtToken;
      stabilityPool = contracts.stabilityPool;
      troveManager = contracts.troveManager;
      borrowerOperations = contracts.borrowerOperations;
      activePool = contracts.activePool;
      priceFeed = contracts.priceFeedTestnet;
      hintHelpers = contracts.hintHelpers;
      sortedTroves = contracts.sortedTroves;

      await priceFeed.setPrice(dec(100, 18));

      tokenName = await debtToken.name();
      tokenVersion = await debtToken.version();

      // Setup: Users open troves
      await openTrove(alice, { collAmount: dec(100, "ether"), debtAmount: dec(10000, 18) });
      await openTrove(bob, { collAmount: dec(50, "ether"), debtAmount: dec(3000, 18) });
      await openTrove(carol, { collAmount: dec(50, "ether"), debtAmount: dec(3000, 18) });
    });

    it("should allow gasless debt repayment via EIP-3009", async () => {
      const repayAmount = toBN(dec(1000, 18));

      // Alice signs authorization for Carol to receive tokens
      const from = alice.address;
      const to = carol.address;
      const value = repayAmount;
      const validAfter = 0;
      const validBefore = Math.floor(Date.now() / 1000) + 3600;
      const nonce = randomBytes(32);

      const digest = getTransferWithAuthorizationDigest(
        tokenName,
        debtToken.address,
        chainId,
        tokenVersion,
        from,
        to,
        value,
        validAfter,
        validBefore,
        nonce,
      );

      const { v, r, s } = sign(digest, alicePrivateKey);

      const carolDebtBefore = await getTroveEntireDebt(carol.address);

      // Carol receives tokens via gasless transfer
      await debtToken
        .connect(carol)
        .receiveWithAuthorization(
          from,
          to,
          value,
          validAfter,
          validBefore,
          nonce,
          v,
          hexlify(r),
          hexlify(s),
        );

      // Carol uses received tokens to repay debt
      const hints = await hintHelpers.getApproxHint(
        carolDebtBefore.sub(repayAmount),
        10,
        ZERO_ADDRESS,
      );
      await borrowerOperations
        .connect(carol)
        .repayDebt(repayAmount, hints.hintAddress, hints.hintAddress);

      const carolDebtAfter = await getTroveEntireDebt(carol.address);
      assert.isTrue(carolDebtAfter.lt(carolDebtBefore));
    });

    it("should prevent transfers to borrower operations via EIP-3009", async () => {
      const from = alice.address;
      const to = borrowerOperations.address; // Invalid recipient
      const value = toBN(dec(1000, 18));
      const validAfter = 0;
      const validBefore = Math.floor(Date.now() / 1000) + 3600;
      const nonce = randomBytes(32);

      const digest = getTransferWithAuthorizationDigest(
        tokenName,
        debtToken.address,
        chainId,
        tokenVersion,
        from,
        to,
        value,
        validAfter,
        validBefore,
        nonce,
      );

      const { v, r, s } = sign(digest, alicePrivateKey);

      await assertRevert(
        debtToken.transferWithAuthorization(
          from,
          to,
          value,
          validAfter,
          validBefore,
          nonce,
          v,
          hexlify(r),
          hexlify(s),
        ),
        "DebtToken: Cannot transfer tokens directly to the StabilityPool, TroveManager or BorrowerOps",
      );
    });
  });

  describe("Integration with Liquidations", () => {
    beforeEach(async () => {
      // Reset state
      await hre.network.provider.send("hardhat_reset");

      // Redeploy
      const transactionCount = await owner.getTransactionCount();
      const cpContracts = await deploymentHelper.computeCoreProtocolContracts(
        owner.address,
        transactionCount,
      );

      contracts = await deploymentHelper.deployProtocolCore(
        GAS_COMPENSATION,
        MIN_NET_DEBT,
        cpContracts,
      );

      debtToken = contracts.debtToken;
      stabilityPool = contracts.stabilityPool;
      troveManager = contracts.troveManager;
      borrowerOperations = contracts.borrowerOperations;
      activePool = contracts.activePool;
      priceFeed = contracts.priceFeedTestnet;
      sortedTroves = contracts.sortedTroves;

      await priceFeed.setPrice(dec(100, 18));

      tokenName = await debtToken.name();
      tokenVersion = await debtToken.version();

      // Setup: Users open troves
      await openTrove(alice, { collAmount: dec(100, "ether"), debtAmount: dec(10000, 18) });
      await openTrove(defaulter_1, { collAmount: dec(20, "ether"), debtAmount: dec(2000, 18) });
      await openTrove(defaulter_2, { collAmount: dec(20, "ether"), debtAmount: dec(2000, 18) });
    });

    it("should allow gasless transfers for liquidation preparation", async () => {
      // Alice signs authorization for Bob to receive tokens
      const from = alice.address;
      const to = bob.address;
      const value = toBN(dec(5000, 18));
      const validAfter = 0;
      const validBefore = Math.floor(Date.now() / 1000) + 3600;
      const nonce = randomBytes(32);

      const digest = getTransferWithAuthorizationDigest(
        tokenName,
        debtToken.address,
        chainId,
        tokenVersion,
        from,
        to,
        value,
        validAfter,
        validBefore,
        nonce,
      );

      const { v, r, s } = sign(digest, alicePrivateKey);

      // Bob receives tokens via gasless transfer
      await debtToken.transferWithAuthorization(
        from,
        to,
        value,
        validAfter,
        validBefore,
        nonce,
        v,
        hexlify(r),
        hexlify(s),
      );

      // Bob deposits to stability pool for liquidations
      await stabilityPool.connect(bob).provideToSP(value, ZERO_ADDRESS);

      // Price drops, making defaulters undercollateralized
      await priceFeed.setPrice(dec(50, 18));

      // Liquidate defaulter_1
      await troveManager.liquidate(defaulter_1.address);

      // Check Bob received liquidation gains
      const bobGain = await stabilityPool.getDepositorFilGain(bob.address);
      assert.isTrue(bobGain.gt(0));
    });
  });

  describe("Upgrade compatibility", () => {
    it("should maintain existing functionality after EIP-3009 addition", async () => {
      // Regular transfer should still work
      const transferAmount = toBN(dec(100, 18));
      await debtToken.connect(alice).transfer(bob.address, transferAmount);

      const bobBalance = await debtToken.balanceOf(bob.address);
      assert.isTrue(bobBalance.gte(transferAmount));

      // Approve and transferFrom should still work
      await debtToken.connect(alice).approve(bob.address, transferAmount);
      await debtToken.connect(bob).transferFrom(alice.address, carol.address, transferAmount);

      const carolBalance = await debtToken.balanceOf(carol.address);
      assert.isTrue(carolBalance.eq(transferAmount));

      // EIP-2612 permit should still work
      // (Test would require permit signature setup)
    });
  });
});
