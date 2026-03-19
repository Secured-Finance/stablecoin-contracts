const deploymentHelper = require("../utils/testDeploymentHelpers.js");
const testHelpers = require("../utils/testHelpers.js");
const th = testHelpers.TestHelper;

const { dec, toBN, assertRevert } = th;

contract("PythCaller", async (accounts) => {
  let pythCaller;
  let mockPyth;
  const priceId = "0x" + "1".repeat(64); // 32 bytes hex string
  const description = "ETH/USD";

  beforeEach(async () => {
    const mockPythFactory = await deploymentHelper.getFactory("MockPyth");
    const pythCallerFactory = await deploymentHelper.getFactory("PythCaller");

    mockPyth = await mockPythFactory.deploy();

    // Set a default price with valid expo range
    await mockPyth.setPrice(
      priceId,
      200000000000, // price: 2000 with 8 decimals
      1000000, // conf
      -8, // expo (valid range: -18 to -1)
      Math.floor(Date.now() / 1000), // current timestamp
    );

    pythCaller = await pythCallerFactory.deploy(mockPyth.address, priceId, description);
  });

  describe("Constructor", async () => {
    it("should set priceId correctly", async () => {
      const storedPriceId = await pythCaller.priceId();
      assert.equal(storedPriceId, priceId);
    });

    it("should set pyth address correctly", async () => {
      const storedPyth = await pythCaller.pyth();
      assert.equal(storedPyth, mockPyth.address);
    });

    it("should set description correctly", async () => {
      const storedDescription = await pythCaller.description();
      assert.equal(storedDescription, description);
    });
  });

  describe("version()", async () => {
    it("should return version 1", async () => {
      const version = await pythCaller.version();
      assert.equal(version.toString(), "1");
    });
  });

  describe("description()", async () => {
    it("should return the correct description", async () => {
      const desc = await pythCaller.description();
      assert.equal(desc, description);
    });
  });

  describe("decimals()", async () => {
    it("should return correct decimals when expo is -8", async () => {
      await mockPyth.setPrice(priceId, 200000000000, 1000000, -8, Math.floor(Date.now() / 1000));
      const decimals = await pythCaller.decimals();
      assert.equal(decimals.toString(), "8");
    });

    it("should return correct decimals when expo is -18", async () => {
      await mockPyth.setPrice(priceId, 200000000000, 1000000, -18, Math.floor(Date.now() / 1000));
      const decimals = await pythCaller.decimals();
      assert.equal(decimals.toString(), "18");
    });

    it("should return correct decimals when expo is -1", async () => {
      await mockPyth.setPrice(priceId, 200000000000, 1000000, -1, Math.floor(Date.now() / 1000));
      const decimals = await pythCaller.decimals();
      assert.equal(decimals.toString(), "1");
    });

    it("should revert when expo is 0 (not negative)", async () => {
      await mockPyth.setPrice(priceId, 200000000000, 1000000, 0, Math.floor(Date.now() / 1000));
      await assertRevert(pythCaller.decimals(), "PythCaller: expo out of range");
    });

    it("should revert when expo is positive", async () => {
      await mockPyth.setPrice(priceId, 200000000000, 1000000, 5, Math.floor(Date.now() / 1000));
      await assertRevert(pythCaller.decimals(), "PythCaller: expo out of range");
    });

    it("should revert when expo is less than -18", async () => {
      await mockPyth.setPrice(priceId, 200000000000, 1000000, -19, Math.floor(Date.now() / 1000));
      await assertRevert(pythCaller.decimals(), "PythCaller: expo out of range");
    });

    it("should revert when expo is -20", async () => {
      await mockPyth.setPrice(priceId, 200000000000, 1000000, -20, Math.floor(Date.now() / 1000));
      await assertRevert(pythCaller.decimals(), "PythCaller: expo out of range");
    });
  });

  describe("getRoundData()", async () => {
    it("should return correct round data", async () => {
      const price = 200000000000;
      const publishTime = Math.floor(Date.now() / 1000);
      await mockPyth.setPrice(priceId, price, 1000000, -8, publishTime);

      const roundId = 12345;
      const result = await pythCaller.getRoundData(roundId);

      assert.equal(result.roundId.toString(), roundId.toString());
      assert.equal(result.answer.toString(), price.toString());
      assert.equal(result.startedAt.toString(), publishTime.toString());
      assert.equal(result.updatedAt.toString(), publishTime.toString());
      assert.equal(result.answeredInRound.toString(), publishTime.toString());
    });

    it("should return data for any roundId (roundId is passed through)", async () => {
      const price = 150000000000;
      const publishTime = Math.floor(Date.now() / 1000);
      await mockPyth.setPrice(priceId, price, 1000000, -8, publishTime);

      const roundId = 99999;
      const result = await pythCaller.getRoundData(roundId);

      assert.equal(result.roundId.toString(), roundId.toString());
      assert.equal(result.answer.toString(), price.toString());
    });

    it("should handle negative price", async () => {
      const price = -100000000000;
      const publishTime = Math.floor(Date.now() / 1000);
      await mockPyth.setPrice(priceId, price, 1000000, -8, publishTime);

      const roundId = 1;
      const result = await pythCaller.getRoundData(roundId);

      assert.equal(result.answer.toString(), price.toString());
    });
  });

  describe("latestRoundData()", async () => {
    it("should return correct latest round data", async () => {
      const price = 200000000000;
      const publishTime = Math.floor(Date.now() / 1000);
      await mockPyth.setPrice(priceId, price, 1000000, -8, publishTime);

      const result = await pythCaller.latestRoundData();

      assert.equal(result.roundId.toString(), publishTime.toString());
      assert.equal(result.answer.toString(), price.toString());
      assert.equal(result.startedAt.toString(), publishTime.toString());
      assert.equal(result.updatedAt.toString(), publishTime.toString());
      assert.equal(result.answeredInRound.toString(), publishTime.toString());
    });

    it("should update when price changes", async () => {
      const price1 = 200000000000;
      const publishTime1 = Math.floor(Date.now() / 1000);
      await mockPyth.setPrice(priceId, price1, 1000000, -8, publishTime1);

      const result1 = await pythCaller.latestRoundData();
      assert.equal(result1.answer.toString(), price1.toString());

      const price2 = 300000000000;
      const publishTime2 = publishTime1 + 100;
      await mockPyth.setPrice(priceId, price2, 1000000, -8, publishTime2);

      const result2 = await pythCaller.latestRoundData();
      assert.equal(result2.answer.toString(), price2.toString());
      assert.equal(result2.roundId.toString(), publishTime2.toString());
    });

    it("should handle zero price", async () => {
      const price = 0;
      const publishTime = Math.floor(Date.now() / 1000);
      await mockPyth.setPrice(priceId, price, 1000000, -8, publishTime);

      const result = await pythCaller.latestRoundData();
      assert.equal(result.answer.toString(), "0");
    });

    it("should handle negative price", async () => {
      const price = -50000000000;
      const publishTime = Math.floor(Date.now() / 1000);
      await mockPyth.setPrice(priceId, price, 1000000, -8, publishTime);

      const result = await pythCaller.latestRoundData();
      assert.equal(result.answer.toString(), price.toString());
    });
  });

  describe("updateFeeds()", async () => {
    it("should update feeds successfully with exact fee", async () => {
      const updateFee = toBN(dec(1, 16)); // 0.01 ETH
      await mockPyth.setUpdateFee(updateFee);

      const priceUpdateData = ["0x1234"]; // dummy data
      await pythCaller.updateFeeds(priceUpdateData, { value: updateFee, from: accounts[0] });

      // Should succeed without reverting
    });

    it("should update feeds successfully with excess fee and refund", async () => {
      const updateFee = toBN(dec(1, 16)); // 0.01 ETH
      const sentValue = toBN(dec(2, 16)); // 0.02 ETH
      await mockPyth.setUpdateFee(updateFee);

      const priceUpdateData = ["0x1234"];
      const balanceBefore = toBN(await web3.eth.getBalance(accounts[0]));

      const tx = await pythCaller.updateFeeds(priceUpdateData, {
        value: sentValue,
        from: accounts[0],
      });

      const receipt = await tx.wait();
      const gasUsed = receipt.gasUsed;
      const txInfo = await web3.eth.getTransaction(receipt.transactionHash);
      const gasPrice = toBN(txInfo.gasPrice);
      const gasCost = gasUsed.mul(gasPrice);

      const balanceAfter = toBN(await web3.eth.getBalance(accounts[0]));

      // Balance should decrease by approximately updateFee + gasCost
      const expectedBalance = balanceBefore.sub(updateFee).sub(gasCost);
      const diff = balanceAfter.sub(expectedBalance).abs();

      // Allow small difference due to refund gas costs
      assert.isTrue(diff.lt(toBN(dec(1, 15)))); // Less than 0.001 ETH difference
    });

    it("should work with zero fee", async () => {
      await mockPyth.setUpdateFee(0);

      const priceUpdateData = ["0x1234"];
      await pythCaller.updateFeeds(priceUpdateData, { value: 0, from: accounts[0] });

      // Should succeed
    });

    it("should work with empty update data", async () => {
      const updateFee = toBN(dec(1, 16));
      await mockPyth.setUpdateFee(updateFee);

      const priceUpdateData = [];
      await pythCaller.updateFeeds(priceUpdateData, { value: updateFee, from: accounts[0] });

      // Should succeed
    });

    it("should work with multiple price update data", async () => {
      const updateFee = toBN(dec(1, 16));
      await mockPyth.setUpdateFee(updateFee);

      const priceUpdateData = ["0x1234", "0x5678", "0xabcd"];
      await pythCaller.updateFeeds(priceUpdateData, { value: updateFee, from: accounts[0] });

      // Should succeed
    });
  });

  describe("Integration tests", async () => {
    it("should work end-to-end: update feeds and read latest data", async () => {
      const updateFee = toBN(dec(1, 16));
      await mockPyth.setUpdateFee(updateFee);

      // Update the price
      const newPrice = 250000000000;
      const newPublishTime = Math.floor(Date.now() / 1000) + 1000;
      await mockPyth.setPrice(priceId, newPrice, 1000000, -8, newPublishTime);

      // Update feeds
      const priceUpdateData = ["0x1234"];
      await pythCaller.updateFeeds(priceUpdateData, { value: updateFee, from: accounts[0] });

      // Read latest data
      const result = await pythCaller.latestRoundData();
      assert.equal(result.answer.toString(), newPrice.toString());
      assert.equal(result.roundId.toString(), newPublishTime.toString());
    });

    it("should maintain consistency between getRoundData and latestRoundData", async () => {
      const price = 180000000000;
      const publishTime = Math.floor(Date.now() / 1000);
      await mockPyth.setPrice(priceId, price, 1000000, -8, publishTime);

      const latestData = await pythCaller.latestRoundData();
      const roundData = await pythCaller.getRoundData(latestData.roundId);

      assert.equal(roundData.answer.toString(), latestData.answer.toString());
      assert.equal(roundData.startedAt.toString(), latestData.startedAt.toString());
      assert.equal(roundData.updatedAt.toString(), latestData.updatedAt.toString());
    });
  });
});
