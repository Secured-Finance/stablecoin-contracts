const deploymentHelper = require("../utils/testDeploymentHelpers.js");
const testHelpers = require("../utils/testHelpers.js");

const th = testHelpers.TestHelper;

const dec = th.dec;
const toBN = th.toBN;
const assertRevert = th.assertRevertWithoutAutomine;

contract("BorrowerOperations - Trove Action Block Tests", async () => {
  let owner, alice, bob, carol;
  let lpRewardsAddress, multisig;

  let troveManager;
  let borrowerOperations;
  let stabilityPool;

  let contracts;

  before(async () => {
    const signers = await ethers.getSigners();

    [owner, alice, bob, carol] = signers;
    [lpRewardsAddress, multisig] = signers.slice(998, 1000);
  });

  beforeEach(async () => {
    await hre.network.provider.send("hardhat_reset");

    const transactionCount = await owner.getTransactionCount();
    const cpTesterContracts = await deploymentHelper.computeContractAddresses(
      owner.address,
      transactionCount,
      7,
    );
    const cpContracts = await deploymentHelper.computeCoreProtocolContracts(
      owner.address,
      transactionCount + 7,
    );

    // Overwrite contracts with computed tester addresses
    cpContracts.troveManager = cpTesterContracts[2];
    cpContracts.borrowerOperations = cpTesterContracts[4];
    cpContracts.debtToken = cpTesterContracts[6];

    const troveManagerTester = await deploymentHelper.deployTroveManagerTester(
      th.GAS_COMPENSATION,
      th.MIN_NET_DEBT,
      cpContracts,
    );
    const borrowerOperationsTester = await deploymentHelper.deployBorrowerOperationsTester(
      th.GAS_COMPENSATION,
      th.MIN_NET_DEBT,
      cpContracts,
    );
    const debtTokenTester = await deploymentHelper.deployDebtTokenTester(cpContracts);

    contracts = await deploymentHelper.deployProtocolCore(
      th.GAS_COMPENSATION,
      th.MIN_NET_DEBT,
      cpContracts,
    );

    contracts.troveManager = troveManagerTester;
    contracts.borrowerOperations = borrowerOperationsTester;
    contracts.debtToken = debtTokenTester;

    const protocolTokenContracts = await deploymentHelper.deployProtocolTokenTesterContracts(
      owner.address,
      cpContracts,
    );

    const allocation = [
      { address: multisig.address, amount: toBN(dec(67000000, 18)) },
      { address: lpRewardsAddress.address, amount: toBN(dec(1000000, 18)) },
      {
        address: protocolTokenContracts.communityIssuance.address,
        amount: toBN(dec(32000000, 18)),
      },
    ];
    await deploymentHelper.allocateProtocolToken(protocolTokenContracts, allocation);

    priceFeed = contracts.priceFeedTestnet;
    debtToken = contracts.debtToken;
    sortedTroves = contracts.sortedTroves;
    troveManager = contracts.troveManager;
    activePool = contracts.activePool;
    defaultPool = contracts.defaultPool;
    borrowerOperations = contracts.borrowerOperations;
    stabilityPool = contracts.stabilityPool;

    protocolTokenStaking = protocolTokenContracts.protocolTokenStaking;
    protocolToken = protocolTokenContracts.protocolToken;

    GAS_COMPENSATION = await borrowerOperations.GAS_COMPENSATION();
    MIN_NET_DEBT = await borrowerOperations.MIN_NET_DEBT();
    BORROWING_FEE_FLOOR = await borrowerOperations.BORROWING_FEE_FLOOR();
  });

  afterEach(async () => {
    await hre.network.provider.send("evm_setAutomine", [true]);
  });

  describe("_requireTroveActionNotInLatestBlock", async () => {
    const REVERT_MESSAGE = "BorrowerOps: Trove action already performed in the latest block";

    it("openTrove(): reverts when called twice trove-related action in the same block", async () => {
      await hre.network.provider.send("evm_setAutomine", [false]);

      await borrowerOperations
        .connect(alice)
        .openTrove(th._100pct, dec(20000, 18), alice.address, alice.address, {
          value: dec(40000, 18),
        });

      const tx = await borrowerOperations
        .connect(alice)
        .openTrove(th._100pct, dec(20000, 18), alice.address, alice.address, {
          value: dec(40000, 18),
        });
      await hre.network.provider.send("evm_mine");

      await assertRevert(tx, REVERT_MESSAGE);
    });

    it("addColl(): reverts when called twice trove-related action in the same block", async () => {
      await hre.network.provider.send("evm_setAutomine", [false]);

      await borrowerOperations
        .connect(alice)
        .openTrove(th._100pct, dec(20000, 18), alice.address, alice.address, {
          value: dec(40000, 18),
        });

      // Second addColl in the same block should revert
      const tx = await borrowerOperations
        .connect(alice)
        .addColl(alice.address, alice.address, { value: dec(100, 18) });

      await hre.network.provider.send("evm_mine");

      await assertRevert(tx, REVERT_MESSAGE);
    });

    it("withdrawColl(): reverts when called twice trove-related action in the same block", async () => {
      await hre.network.provider.send("evm_setAutomine", [false]);

      await borrowerOperations
        .connect(alice)
        .openTrove(th._100pct, dec(20000, 18), alice.address, alice.address, {
          value: dec(40000, 18),
        });

      const tx = await borrowerOperations
        .connect(alice)
        .withdrawColl(dec(100, 18), alice.address, alice.address);
      await hre.network.provider.send("evm_mine");

      await assertRevert(tx, REVERT_MESSAGE);
    });

    it("withdrawDebtToken(): reverts when called twice trove-related action in the same block", async () => {
      await hre.network.provider.send("evm_setAutomine", [false]);

      await borrowerOperations
        .connect(alice)
        .openTrove(th._100pct, dec(20000, 18), alice.address, alice.address, {
          value: dec(40000, 18),
        });

      const tx = await borrowerOperations
        .connect(alice)
        .withdrawDebtToken(th._100pct, dec(50, 18), alice.address, alice.address);
      await hre.network.provider.send("evm_mine");

      await assertRevert(tx, REVERT_MESSAGE);
    });

    it("repayDebtToken(): reverts when called twice trove-related action in the same block", async () => {
      await hre.network.provider.send("evm_setAutomine", [false]);

      await borrowerOperations
        .connect(alice)
        .openTrove(th._100pct, dec(20000, 18), alice.address, alice.address, {
          value: dec(40000, 18),
        });

      const tx = await borrowerOperations
        .connect(alice)
        .repayDebtToken(dec(50, 18), alice.address, alice.address);
      await hre.network.provider.send("evm_mine");

      await assertRevert(tx, REVERT_MESSAGE);
    });

    it("adjustTrove(): reverts when called twice trove-related action in the same block", async () => {
      await hre.network.provider.send("evm_setAutomine", [false]);

      await borrowerOperations
        .connect(alice)
        .openTrove(th._100pct, dec(20000, 18), alice.address, alice.address, {
          value: dec(40000, 18),
        });

      const tx = await borrowerOperations
        .connect(alice)
        .adjustTrove(th._100pct, 0, dec(50, 18), true, alice.address, alice.address, {
          value: 0,
        });
      await hre.network.provider.send("evm_mine");

      await assertRevert(tx, REVERT_MESSAGE);
    });

    it("closeTrove(): reverts when called twice trove-related action in the same block", async () => {
      await hre.network.provider.send("evm_setAutomine", [false]);

      await borrowerOperations
        .connect(alice)
        .openTrove(th._100pct, dec(20000, 18), alice.address, alice.address, {
          value: dec(40000, 18),
        });

      const tx = await borrowerOperations.connect(alice).closeTrove();
      await hre.network.provider.send("evm_mine");

      await assertRevert(tx, REVERT_MESSAGE);
    });

    it("moveFILGainToTrove(): reverts when called twice trove-related action in the same block", async () => {
      // Send some FIL to the stability pool
      await hre.network.provider.send("hardhat_setBalance", [
        stabilityPool.address,
        ethers.utils.parseEther("1000").toHexString(),
      ]);
      const spUser = await ethers.getImpersonatedSigner(stabilityPool.address);
      await hre.network.provider.send("evm_setAutomine", [false]);

      // Create a trove first
      await borrowerOperations
        .connect(alice)
        .openTrove(th._100pct, dec(20000, 18), alice.address, alice.address, {
          value: dec(40000, 18),
        });

      // First moveFILGainToTrove in the same block should revert
      const tx = await borrowerOperations
        .connect(spUser)
        .moveFILGainToTrove(alice.address, alice.address, alice.address, {
          value: dec(100, 18),
        });

      await hre.network.provider.send("evm_mine");

      await assertRevert(tx, REVERT_MESSAGE);
    });

    it("allows different trove-related actions in different blocks", async () => {
      // Create a trove first
      await borrowerOperations
        .connect(alice)
        .openTrove(th._100pct, dec(20000, 18), alice.address, alice.address, {
          value: dec(40000, 18),
        });

      // First action in block 1
      await borrowerOperations
        .connect(alice)
        .addColl(alice.address, alice.address, { value: dec(100, 18) });

      // Mine a new block
      await hre.network.provider.send("evm_mine");

      // Second action in block 2 should succeed
      await borrowerOperations
        .connect(alice)
        .withdrawColl(dec(50, 18), alice.address, alice.address);
    });

    it("allows different users to perform actions in the same block", async () => {
      // Alice creates a trove
      await borrowerOperations
        .connect(alice)
        .openTrove(th._100pct, dec(20000, 18), alice.address, alice.address, {
          value: dec(40000, 18),
        });

      // Bob creates a trove
      await borrowerOperations
        .connect(bob)
        .openTrove(th._100pct, dec(20000, 18), bob.address, bob.address, {
          value: dec(40000, 18),
        });

      // Alice performs an action
      await borrowerOperations
        .connect(alice)
        .addColl(alice.address, alice.address, { value: dec(100, 18) });

      // Bob should still be able to perform an action in the same block
      await borrowerOperations
        .connect(bob)
        .addColl(bob.address, bob.address, { value: dec(100, 18) });
    });

    it("lastTroveActionBlock mapping is updated correctly", async () => {
      // Create a trove first
      await borrowerOperations
        .connect(alice)
        .openTrove(th._100pct, dec(20000, 18), alice.address, alice.address, {
          value: dec(40000, 18),
        });

      const currentBlock = await ethers.provider.getBlockNumber();

      // Perform an action
      await borrowerOperations
        .connect(alice)
        .addColl(alice.address, alice.address, { value: dec(100, 18) });

      // Check that lastTroveActionBlock was updated
      const lastActionBlock = await borrowerOperations.lastTroveActionBlock(alice.address);
      assert.equal(lastActionBlock.toString(), (currentBlock + 1).toString());
    });

    it("lastTroveActionBlock is updated for each trove action", async () => {
      // Create a trove first
      await borrowerOperations
        .connect(alice)
        .openTrove(th._100pct, dec(20000, 18), alice.address, alice.address, {
          value: dec(40000, 18),
        });

      // Perform multiple actions in different blocks
      await borrowerOperations
        .connect(alice)
        .addColl(alice.address, alice.address, { value: dec(100, 18) });

      await hre.network.provider.send("evm_mine");

      await borrowerOperations
        .connect(alice)
        .withdrawColl(dec(50, 18), alice.address, alice.address);

      await hre.network.provider.send("evm_mine");

      await borrowerOperations
        .connect(alice)
        .withdrawDebtToken(th._100pct, dec(25, 18), alice.address, alice.address);

      // Check that lastTroveActionBlock was updated to the latest block
      const lastActionBlock = await borrowerOperations.lastTroveActionBlock(alice.address);
      const currentBlock = await ethers.provider.getBlockNumber();
      assert.equal(lastActionBlock.toString(), currentBlock.toString());
    });

    it("allows different types of trove actions in the same block for different users", async () => {
      // Alice creates a trove
      await borrowerOperations
        .connect(alice)
        .openTrove(th._100pct, dec(20000, 18), alice.address, alice.address, {
          value: dec(40000, 18),
        });

      // Bob creates a trove
      await borrowerOperations
        .connect(bob)
        .openTrove(th._100pct, dec(20000, 18), bob.address, bob.address, {
          value: dec(40000, 18),
        });

      // Alice adds collateral
      await borrowerOperations
        .connect(alice)
        .addColl(alice.address, alice.address, { value: dec(100, 18) });

      // Bob withdraws debt tokens
      await borrowerOperations
        .connect(bob)
        .withdrawDebtToken(th._100pct, dec(50, 18), bob.address, bob.address);

      // Carol creates a trove
      await borrowerOperations
        .connect(carol)
        .openTrove(th._100pct, dec(20000, 18), carol.address, carol.address, {
          value: dec(40000, 18),
        });

      // All actions should succeed in the same block
      assert.equal(
        (await troveManager.getTroveStatus(alice.address)).toString(),
        "1",
        "Alice's trove should be active",
      );
      assert.equal(
        (await troveManager.getTroveStatus(bob.address)).toString(),
        "1",
        "Bob's trove should be active",
      );
      assert.equal(
        (await troveManager.getTroveStatus(carol.address)).toString(),
        "1",
        "Carol's trove should be active",
      );
    });

    it("prevents rapid successive actions by the same user", async () => {
      await hre.network.provider.send("evm_setAutomine", [false]);

      // First action should succeed
      await borrowerOperations
        .connect(alice)
        .openTrove(th._100pct, dec(20000, 18), alice.address, alice.address, {
          value: dec(40000, 18),
        });

      // Second action in the same block should fail
      const tx2 = await borrowerOperations
        .connect(alice)
        .addColl(alice.address, alice.address, { value: dec(100, 18) });

      // Third action in the same block should also fail
      const tx3 = await borrowerOperations
        .connect(alice)
        .withdrawColl(dec(50, 18), alice.address, alice.address);

      await hre.network.provider.send("evm_mine");

      await assertRevert(tx2, REVERT_MESSAGE);

      await assertRevert(tx3, REVERT_MESSAGE);
    });
  });
});
