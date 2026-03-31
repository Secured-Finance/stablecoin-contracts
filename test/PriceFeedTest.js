const deploymentHelper = require("../utils/testDeploymentHelpers.js");
const testHelpers = require("../utils/testHelpers.js");
const th = testHelpers.TestHelper;

const { dec, toBN, assertRevert } = th;

contract("PriceFeed", async () => {
  let priceFeedTestnet;
  let priceFeed;
  let mockChainlink;

  let mockTellor;
  let tellorCaller;

  beforeEach(async () => {
    const priceFeedTestnetFactory = await deploymentHelper.getFactory("PriceFeedTestnet");
    const priceFeedTesterFactory = await deploymentHelper.getFactory("PriceFeedTester");
    const mockChainlinkFactory = await deploymentHelper.getFactory("MockAggregator");
    const mockTellorFactory = await deploymentHelper.getFactory("MockTellor");
    const tellorCallerFactory = await deploymentHelper.getFactory("TellorCaller");

    priceFeedTestnet = await priceFeedTestnetFactory.deploy();
    mockChainlink = await mockChainlinkFactory.deploy();
    mockTellor = await mockTellorFactory.deploy();
    tellorCaller = await tellorCallerFactory.deploy(mockTellor.address);

    // Set Chainlink latest and prev round Id's to non-zero
    await mockChainlink.setLatestRoundId(3);
    await mockChainlink.setPrevRoundId(2);

    //Set current and prev prices in both oracles
    await mockChainlink.setPrice(dec(100, 8));
    await mockTellor.setPrice(dec(100, 18));

    // Set mock price updateTimes in both oracles to very recent
    const now = await th.getLatestBlockTimestamp(web3);
    await mockChainlink.setUpdateTime(now);
    await mockTellor.setUpdateTime(now);

    priceFeed = await deploymentHelper.deployProxy(
      priceFeedTesterFactory,
      [mockChainlink.address, tellorCaller.address],
      [th.ORACLE_TIMEOUT, th.LAST_GOOD_PRICE_TIMEOUT],
    );
  });

  describe("PriceFeed internal testing contract", async (accounts) => {
    it("fetchPrice before setPrice should return the default price", async () => {
      const price = await priceFeedTestnet.getPrice();
      assert.equal(price.toString(), dec(200, 18));
    });
    it("should be able to fetchPrice after setPrice, output of former matching input of latter", async () => {
      await priceFeedTestnet.setPrice(dec(100, 8));
      const price = await priceFeedTestnet.getPrice();
      assert.equal(price.toString(), dec(100, 8));
    });
  });

  describe("Mainnet PriceFeed setup", async (accounts) => {
    it("PriceFeed deployment should fail with wrong chainlink address set", async () => {
      const nonPayableFactory = await deploymentHelper.getFactory("NonPayable");
      const priceFeedTesterFactory = await deploymentHelper.getFactory("PriceFeedTester");

      const dumbContract = await nonPayableFactory.deploy();

      await assertRevert(
        deploymentHelper.deployProxy(
          priceFeedTesterFactory,
          [dumbContract.address, dumbContract.address],
          [th.ORACLE_TIMEOUT, th.LAST_GOOD_PRICE_TIMEOUT],
        ),
      );
    });
  });

  it("C1 Chainlink working: fetchPrice should return the correct price, taking into account the number of decimal digits on the aggregator", async () => {
    // Oracle price price is 10.00000000
    await mockChainlink.setDecimals(8);
    await mockChainlink.setPrice(dec(1, 9));
    await priceFeed.setLastGoodPrice(dec(11, 18));
    await priceFeed.fetchPrice();
    let price = await priceFeed.lastGoodPrice();
    // Check protocol PriceFeed gives 10, with 18 digit precision
    assert.equal(price.toString(), dec(10, 18));

    // Oracle price is 1e9
    await mockChainlink.setDecimals(0);
    await mockChainlink.setPrice(dec(1, 9));
    await priceFeed.setLastGoodPrice(dec(11, 26));
    await priceFeed.fetchPrice();
    price = await priceFeed.lastGoodPrice();
    // Check protocol PriceFeed gives 1e9, with 18 digit precision
    assert.isTrue(price.eq(toBN(dec(10, 26))));

    // Oracle price is 0.0001
    await mockChainlink.setDecimals(18);
    const decimals = await mockChainlink.decimals();

    await mockChainlink.setPrice(dec(10, 13));
    await priceFeed.setLastGoodPrice(dec(11, 13));
    await priceFeed.fetchPrice();
    price = await priceFeed.lastGoodPrice();
    // Check protocol PriceFeed gives 0.0001 with 18 digit precision
    assert.isTrue(price.eq(toBN(dec(10, 13))));

    // Oracle price is 1234.56789
    await mockChainlink.setDecimals(5);
    await mockChainlink.setPrice(dec(123456789));
    await priceFeed.setLastGoodPrice("1334567890000000000000");
    await priceFeed.fetchPrice();
    price = await priceFeed.lastGoodPrice();
    // Check protocol PriceFeed gives 0.0001 with 18 digit precision
    assert.equal(price.toString(), "1234567890000000000000");
  });

  // --- Chainlink breaks ---
  it("C1 Chainlink breaks, Tellor working: fetchPrice should return the correct Tellor price, taking into account Tellor's 6-digit granularity", async () => {
    // --- Chainlink fails, system switches to Tellor ---
    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    // Chainlink breaks with negative price
    await mockChainlink.setPrice("-5000");

    await mockTellor.setPrice(dec(123, 18));
    await mockChainlink.setUpdateTime(0);

    const priceFetchTx = await priceFeed.fetchPrice();
    const statusAfter = await priceFeed.status();
    assert.equal(statusAfter, "1"); // status 1: using Tellor, Chainlink untrusted

    let price = await priceFeed.lastGoodPrice();
    assert.equal(price.toString(), dec(123, 18));

    const now = await th.getLatestBlockTimestamp(web3);

    // Tellor price is 10 at 6-digit precision
    await mockTellor.setPrice(dec(10, 8));
    await mockTellor.setUpdateTime(now);
    await priceFeed.fetchPrice();
    price = await priceFeed.lastGoodPrice();
    // Check protocol PriceFeed gives 10, with 18 digit precision
    assert.equal(price.toString(), dec(10, 8));

    // Tellor price is 1e9 at 6-digit precision
    await mockTellor.setPrice(dec(1, 27));
    await mockTellor.setUpdateTime(now + 1);
    await priceFeed.fetchPrice();
    price = await priceFeed.lastGoodPrice();
    // Check protocol PriceFeed gives 1e9, with 18 digit precision
    assert.equal(price.toString(), dec(1, 27));

    // Tellor price is 0.0001 at 6-digit precision
    await mockTellor.setPrice(dec(1, 14));
    await mockTellor.setUpdateTime(now + 2);
    await priceFeed.fetchPrice();
    price = await priceFeed.lastGoodPrice();
    // Check protocol PriceFeed gives 0.0001 with 18 digit precision

    assert.equal(price.toString(), dec(1, 14));

    // Tellor price is 1234.56789 at 6-digit precision
    await mockTellor.setPrice(dec("1234567890000000000000"));
    await mockTellor.setUpdateTime(now + 3);
    await priceFeed.fetchPrice();
    price = await priceFeed.lastGoodPrice();
    // Check protocol PriceFeed gives 0.0001 with 18 digit precision
    assert.equal(price.toString(), "1234567890000000000000");
  });

  it("C1 chainlinkWorking: Chainlink broken by zero latest roundId, Tellor working: switch to usingChainlinkTellorUntrusted", async () => {
    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await mockChainlink.setPrice(dec(999, 8));
    await priceFeed.setLastGoodPrice(dec(999, 18));

    await mockTellor.setPrice(dec(123, 18));
    await mockChainlink.setLatestRoundId(0);

    const priceFetchTx = await priceFeed.fetchPrice();
    const statusAfter = await priceFeed.status();
    assert.equal(statusAfter, "1"); // status 1: using Tellor, Chainlink untrusted
  });

  it("C1 chainlinkWorking: Chainlink broken by zero latest roundId, Tellor working: use Tellor price", async () => {
    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await mockChainlink.setPrice(dec(999, 8));
    await priceFeed.setLastGoodPrice(dec(999, 18));

    await mockTellor.setPrice(dec(123, 18));
    await mockChainlink.setLatestRoundId(0);

    const priceFetchTx = await priceFeed.fetchPrice();
    const statusAfter = await priceFeed.status();
    assert.equal(statusAfter, "1"); // status 1: using Tellor, Chainlink untrusted
  });

  it("C1 chainlinkWorking: Chainlink broken by zero timestamp, Tellor working, switch to usingChainlinkTellorUntrusted", async () => {
    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await mockChainlink.setPrice(dec(999, 8));
    await priceFeed.setLastGoodPrice(dec(999, 18));

    await mockTellor.setPrice(dec(123, 18));
    await mockChainlink.setUpdateTime(0);

    const priceFetchTx = await priceFeed.fetchPrice();
    const statusAfter = await priceFeed.status();
    assert.equal(statusAfter, "1"); // status 1: using Tellor, Chainlink untrusted
  });

  it("C1 chainlinkWorking:  Chainlink broken by zero timestamp, Tellor working, return Tellor price", async () => {
    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await mockChainlink.setPrice(dec(999, 8));
    await priceFeed.setLastGoodPrice(dec(999, 18));

    await mockTellor.setPrice(dec(123, 18));
    await mockChainlink.setUpdateTime(0);

    const priceFetchTx = await priceFeed.fetchPrice();

    let price = await priceFeed.lastGoodPrice();
    assert.equal(price.toString(), dec(123, 18));
  });

  it("C1 chainlinkWorking: Chainlink broken by future timestamp, Tellor working, switch to usingChainlinkTellorUntrusted", async () => {
    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await mockChainlink.setPrice(dec(999, 8));
    await priceFeed.setLastGoodPrice(dec(999, 18));

    const now = await th.getLatestBlockTimestamp(web3);
    const future = toBN(now).add(toBN("1000"));

    await mockTellor.setPrice(dec(123, 18));
    await mockChainlink.setUpdateTime(future);

    const priceFetchTx = await priceFeed.fetchPrice();
    const statusAfter = await priceFeed.status();
    assert.equal(statusAfter, "1"); // status 1: using Tellor, Chainlink untrusted
  });

  it("C1 chainlinkWorking: Chainlink broken by future timestamp, Tellor working, return Tellor price", async () => {
    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await mockChainlink.setPrice(dec(999, 8));
    await priceFeed.setLastGoodPrice(dec(999, 18));

    const now = await th.getLatestBlockTimestamp(web3);
    const future = toBN(now).add(toBN("1000"));

    await mockTellor.setPrice(dec(123, 18));
    await mockChainlink.setUpdateTime(future);

    const priceFetchTx = await priceFeed.fetchPrice();

    let price = await priceFeed.lastGoodPrice();
    assert.equal(price.toString(), dec(123, 18));
  });

  it("C1 chainlinkWorking: Chainlink broken by negative price, Tellor working,  switch to usingChainlinkTellorUntrusted", async () => {
    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await priceFeed.setLastGoodPrice(dec(999, 18));

    await mockTellor.setPrice(dec(123, 18));
    await mockChainlink.setPrice("-5000");

    const priceFetchTx = await priceFeed.fetchPrice();
    const statusAfter = await priceFeed.status();
    assert.equal(statusAfter, "1"); // status 1: using Tellor, Chainlink untrusted
  });

  it("C1 chainlinkWorking: Chainlink broken by negative price, Tellor working, return Tellor price", async () => {
    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await priceFeed.setLastGoodPrice(dec(999, 18));

    await mockTellor.setPrice(dec(123, 18));
    await mockChainlink.setPrice("-5000");

    const priceFetchTx = await priceFeed.fetchPrice();

    let price = await priceFeed.lastGoodPrice();
    assert.equal(price.toString(), dec(123, 18));
  });

  it("C1 chainlinkWorking: Chainlink broken - decimals call reverted, Tellor working, switch to usingChainlinkTellorUntrusted", async () => {
    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await mockChainlink.setPrice(dec(999, 8));
    await priceFeed.setLastGoodPrice(dec(999, 18));

    await mockTellor.setPrice(dec(123, 18));
    await mockChainlink.setDecimalsRevert();

    const priceFetchTx = await priceFeed.fetchPrice();
    const statusAfter = await priceFeed.status();
    assert.equal(statusAfter, "1"); // status 1: using Tellor, Chainlink untrusted
  });

  it("C1 chainlinkWorking: Chainlink broken - decimals call reverted, Tellor working, return Tellor price", async () => {
    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await mockChainlink.setPrice(dec(999, 8));
    await priceFeed.setLastGoodPrice(dec(999, 18));

    await mockTellor.setPrice(dec(123, 18));
    await mockChainlink.setDecimalsRevert();

    const priceFetchTx = await priceFeed.fetchPrice();

    let price = await priceFeed.lastGoodPrice();
    assert.equal(price.toString(), dec(123, 18));
  });

  it("C1 chainlinkWorking: Chainlink broken - latest round call reverted, Tellor working, switch to usingChainlinkTellorUntrusted", async () => {
    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await mockChainlink.setPrice(dec(999, 8));
    await priceFeed.setLastGoodPrice(dec(999, 18));

    await mockTellor.setPrice(dec(123, 18));
    await mockChainlink.setLatestRevert();

    const priceFetchTx = await priceFeed.fetchPrice();
    const statusAfter = await priceFeed.status();
    assert.equal(statusAfter, "1"); // status 1: using Tellor, Chainlink untrusted
  });

  it("C1 chainlinkWorking: latest round call reverted, Tellor working, return the Tellor price", async () => {
    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await mockChainlink.setPrice(dec(999, 8));
    await priceFeed.setLastGoodPrice(dec(999, 18));

    await mockTellor.setPrice(dec(123, 18));
    await mockChainlink.setLatestRevert();

    const priceFetchTx = await priceFeed.fetchPrice();

    let price = await priceFeed.lastGoodPrice();
    assert.equal(price.toString(), dec(123, 18));
  });

  // --- Chainlink timeout ---

  it("C1 chainlinkWorking: Chainlink frozen, Tellor working: switch to usingTellorChainlinkFrozen", async () => {
    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await mockChainlink.setPrice(dec(999, 8));
    await priceFeed.setLastGoodPrice(dec(999, 18));

    await th.fastForwardTime(14400, web3.currentProvider); // fast forward 4 hours
    const now = await th.getLatestBlockTimestamp(web3);

    // Tellor price is recent
    await mockTellor.setUpdateTime(now);
    await mockTellor.setPrice(dec(123, 18));

    const priceFetchTx = await priceFeed.fetchPrice();
    const statusAfter = await priceFeed.status();
    assert.equal(statusAfter, "3"); // status 3: using Tellor, Chainlink frozen
  });

  it("C1 chainlinkWorking: Chainlink frozen, Tellor working: return Tellor price", async () => {
    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await mockChainlink.setPrice(dec(999, 8));
    await priceFeed.setLastGoodPrice(dec(999, 18));

    await th.fastForwardTime(14400, web3.currentProvider); // Fast forward 4 hours
    const now = await th.getLatestBlockTimestamp(web3);
    // Tellor price is recent
    await mockTellor.setUpdateTime(now);
    await mockTellor.setPrice(dec(123, 18));

    const priceFetchTx = await priceFeed.fetchPrice();

    let price = await priceFeed.lastGoodPrice();
    assert.equal(price.toString(), dec(123, 18));
  });

  it("C1 chainlinkWorking: Chainlink frozen, Tellor frozen: switch to usingTellorChainlinkFrozen", async () => {
    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await mockChainlink.setPrice(dec(999, 8));
    await priceFeed.setLastGoodPrice(dec(999, 18));

    await mockTellor.setPrice(dec(123, 18));

    await th.fastForwardTime(14400, web3.currentProvider); // fast forward 4 hours

    // check Tellor price timestamp is out of date by > 4 hours
    const now = await th.getLatestBlockTimestamp(web3);
    const tellorUpdateTime = await mockTellor.getTimestampbyRequestIDandIndex(0, 0);
    assert.isTrue(tellorUpdateTime.lt(toBN(now).sub(toBN(14400))));

    const priceFetchTx = await priceFeed.fetchPrice();
    const statusAfter = await priceFeed.status();
    assert.equal(statusAfter, "3"); // status 3: using Tellor, Chainlink frozen
  });

  it("C1 chainlinkWorking: Chainlink frozen, Tellor frozen: return last good price", async () => {
    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await mockChainlink.setPrice(dec(999, 8));
    await priceFeed.setLastGoodPrice(dec(999, 18));

    await mockTellor.setPrice(dec(123, 18));

    await th.fastForwardTime(14400, web3.currentProvider); // Fast forward 4 hours

    // check Tellor price timestamp is out of date by > 4 hours
    const now = await th.getLatestBlockTimestamp(web3);
    const tellorUpdateTime = await mockTellor.getTimestampbyRequestIDandIndex(0, 0);
    assert.isTrue(tellorUpdateTime.lt(toBN(now).sub(toBN(14400))));

    const priceFetchTx = await priceFeed.fetchPrice();
    let price = await priceFeed.lastGoodPrice();
    // Expect lastGoodPrice has not updated
    assert.equal(price.toString(), dec(999, 18));
  });

  it("C1 chainlinkWorking: Chainlink times out, Tellor broken by 0 price: switch to usingChainlinkTellorUntrusted", async () => {
    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await mockChainlink.setPrice(dec(999, 8));
    await priceFeed.setLastGoodPrice(dec(999, 18));

    await th.fastForwardTime(14400, web3.currentProvider); // Fast forward 4 hours

    // Tellor breaks by 0 price
    await mockTellor.setPrice(0);

    const priceFetchTx = await priceFeed.fetchPrice();
    const statusAfter = await priceFeed.status();
    assert.equal(statusAfter, "4"); // status 4: using Chainlink, Tellor untrusted
  });

  it("C1 chainlinkWorking: Chainlink times out, Tellor broken by 0 price: return last good price", async () => {
    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await mockChainlink.setPrice(dec(999, 8));
    await priceFeed.setLastGoodPrice(dec(999, 18));

    await th.fastForwardTime(14400, web3.currentProvider); // Fast forward 4 hours

    await mockTellor.setPrice(0);

    const priceFetchTx = await priceFeed.fetchPrice();
    let price = await priceFeed.lastGoodPrice();

    // Expect lastGoodPrice has not updated
    assert.equal(price.toString(), dec(999, 18));
  });

  it("C1 chainlinkWorking: Chainlink is out of date by <3hrs: remain chainlinkWorking", async () => {
    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await mockChainlink.setPrice(dec(1234, 8));
    await priceFeed.setLastGoodPrice(dec(1000, 18));
    await th.fastForwardTime(10740, web3.currentProvider); // fast forward 2hrs 59 minutes

    const priceFetchTx = await priceFeed.fetchPrice();
    const statusAfter = await priceFeed.status();
    assert.equal(statusAfter, "0"); // status 0: Chainlink working
  });

  it("C1 chainlinkWorking: Chainlink is out of date by <3hrs: return Chainklink price", async () => {
    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    const decimals = await mockChainlink.decimals();

    await mockChainlink.setPrice(dec(1234, 8));
    await priceFeed.setLastGoodPrice(dec(1000, 18));
    await th.fastForwardTime(10740, web3.currentProvider); // fast forward 2hrs 59 minutes

    const priceFetchTx = await priceFeed.fetchPrice();
    const price = await priceFeed.lastGoodPrice();
    assert.equal(price.toString(), dec(1234, 18));
  });

  // --- Chainlink price deviation ---

  it("C1 chainlinkWorking: Chainlink price drop of >50%, switch to usingChainlinkTellorUntrusted", async () => {
    priceFeed.setLastGoodPrice(dec(2, 18));

    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await mockTellor.setPrice(dec(203, 16));
    await priceFeed.setLastGoodPrice(dec(2, 18)); // price = 2
    await mockChainlink.setPrice(99999999); // price drops to 0.99999999: a drop of > 50% from previous

    const priceFetchTx = await priceFeed.fetchPrice();
    const statusAfter = await priceFeed.status();
    assert.equal(statusAfter, "1"); // status 1: using Tellor, Chainlink untrusted
  });

  it("C1 chainlinkWorking: Chainlink price drop of >50%, return the Tellor price", async () => {
    priceFeed.setLastGoodPrice(dec(2, 18));

    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await mockTellor.setPrice(dec(203, 16));
    await priceFeed.setLastGoodPrice(dec(2, 18)); // price = 2
    await mockChainlink.setPrice(99999999); // price drops to 0.99999999: a drop of > 50% from previous

    const priceFetchTx = await priceFeed.fetchPrice();

    let price = await priceFeed.lastGoodPrice();

    assert.equal(price, dec(203, 16));
  });

  it("C1 chainlinkWorking: Chainlink price drop of 50%, remain chainlinkWorking", async () => {
    priceFeed.setLastGoodPrice(dec(2, 18));

    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await mockTellor.setPrice(dec(203, 16));
    await priceFeed.setLastGoodPrice(dec(2, 18)); // price = 2
    await mockChainlink.setPrice(dec(1, 8)); // price drops to 1

    const priceFetchTx = await priceFeed.fetchPrice();
    const statusAfter = await priceFeed.status();
    assert.equal(statusAfter, "0"); // status 0: Chainlink working
  });

  it("C1 chainlinkWorking: Chainlink price drop of 50%, return the Chainlink price", async () => {
    priceFeed.setLastGoodPrice(dec(2, 18));

    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await mockTellor.setPrice(dec(203, 16));
    await priceFeed.setLastGoodPrice(dec(2, 18)); // price = 2
    await mockChainlink.setPrice(dec(1, 8)); // price drops to 1

    const priceFetchTx = await priceFeed.fetchPrice();

    let price = await priceFeed.lastGoodPrice();
    assert.equal(price, dec(1, 18));
  });

  it("C1 chainlinkWorking: Chainlink price drop of <50%, remain chainlinkWorking", async () => {
    priceFeed.setLastGoodPrice(dec(2, 18));

    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await mockTellor.setPrice(dec(203, 16));
    await priceFeed.setLastGoodPrice(dec(2, 18)); // price = 2
    await mockChainlink.setPrice(dec(100000001)); // price drops to 1.00000001:  a drop of < 50% from previous

    const priceFetchTx = await priceFeed.fetchPrice();
    const statusAfter = await priceFeed.status();
    assert.equal(statusAfter, "0"); // status 0: Chainlink working
  });

  it("C1 chainlinkWorking: Chainlink price drop of <50%, return Chainlink price", async () => {
    priceFeed.setLastGoodPrice(dec(2, 18));

    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await mockTellor.setPrice(dec(203, 16));
    await priceFeed.setLastGoodPrice(dec(2, 18)); // price = 2
    await mockChainlink.setPrice(100000001); // price drops to 1.00000001:  a drop of < 50% from previous

    const priceFetchTx = await priceFeed.fetchPrice();

    let price = await priceFeed.lastGoodPrice();
    assert.equal(price, dec(100000001, 10));
  });

  // Price increase
  it("C1 chainlinkWorking: Chainlink price increase of >100%, switch to usingChainlinkTellorUntrusted", async () => {
    priceFeed.setLastGoodPrice(dec(2, 18));

    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await mockTellor.setPrice(dec(203, 16));
    await priceFeed.setLastGoodPrice(dec(2, 18)); // price = 2
    await mockChainlink.setPrice(400000001); // price increases to 4.000000001: an increase of > 100% from previous

    const priceFetchTx = await priceFeed.fetchPrice();
    const statusAfter = await priceFeed.status();
    assert.equal(statusAfter, "1"); // status 1: using Tellor, Chainlink untrusted
  });

  it("C1 chainlinkWorking: Chainlink price increase of >100%, return Tellor price", async () => {
    priceFeed.setLastGoodPrice(dec(2, 18));

    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await mockTellor.setPrice(dec(203, 16));
    await priceFeed.setLastGoodPrice(dec(2, 18)); // price = 2
    await mockChainlink.setPrice(400000001); // price increases to 4.000000001: an increase of > 100% from previous

    const priceFetchTx = await priceFeed.fetchPrice();
    let price = await priceFeed.lastGoodPrice();
    assert.equal(price, dec(203, 16));
  });

  it("C1 chainlinkWorking: Chainlink price increase of 100%, remain chainlinkWorking", async () => {
    priceFeed.setLastGoodPrice(dec(2, 18));

    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await mockTellor.setPrice(dec(203, 16));
    await priceFeed.setLastGoodPrice(dec(2, 18)); // price = 2
    await mockChainlink.setPrice(dec(4, 8)); // price increases to 4: an increase of 100% from previous

    const priceFetchTx = await priceFeed.fetchPrice();
    const statusAfter = await priceFeed.status();
    assert.equal(statusAfter, "0"); // status 0: Chainlink working
  });

  it("C1 chainlinkWorking: Chainlink price increase of 100%, return Chainlink price", async () => {
    priceFeed.setLastGoodPrice(dec(2, 18));

    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await mockTellor.setPrice(dec(203, 16));
    await priceFeed.setLastGoodPrice(dec(2, 18)); // price = 2
    await mockChainlink.setPrice(dec(4, 8)); // price increases to 4: an increase of 100% from previous

    const priceFetchTx = await priceFeed.fetchPrice();
    let price = await priceFeed.lastGoodPrice();
    assert.equal(price, dec(4, 18));
  });

  it("C1 chainlinkWorking: Chainlink price increase of <100%, remain chainlinkWorking", async () => {
    priceFeed.setLastGoodPrice(dec(2, 18));

    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await mockTellor.setPrice(dec(203, 16));
    await priceFeed.setLastGoodPrice(dec(2, 18)); // price = 2
    await mockChainlink.setPrice(399999999); // price increases to 3.99999999: an increase of < 100% from previous

    const priceFetchTx = await priceFeed.fetchPrice();
    const statusAfter = await priceFeed.status();
    assert.equal(statusAfter, "0"); // status 0: Chainlink working
  });

  it("C1 chainlinkWorking: Chainlink price increase of <100%,  return Chainlink price", async () => {
    priceFeed.setLastGoodPrice(dec(2, 18));

    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await mockTellor.setPrice(dec(203, 16));
    await priceFeed.setLastGoodPrice(dec(2, 18)); // price = 2
    await mockChainlink.setPrice(399999999); // price increases to 3.99999999: an increase of < 100% from previous

    const priceFetchTx = await priceFeed.fetchPrice();
    let price = await priceFeed.lastGoodPrice();
    assert.equal(price, dec(399999999, 10));
  });

  it("C1 chainlinkWorking: Chainlink price drop of >50% and Tellor price matches: remain chainlinkWorking", async () => {
    priceFeed.setLastGoodPrice(dec(2, 18));

    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await priceFeed.setLastGoodPrice(dec(2, 18)); // price = 2
    await mockChainlink.setPrice(99999999); // price drops to 0.99999999: a drop of > 50% from previous
    await mockTellor.setPrice(dec(99999999, 10)); // Tellor price drops to same value

    const priceFetchTx = await priceFeed.fetchPrice();
    const statusAfter = await priceFeed.status();
    assert.equal(statusAfter, "0"); // status 0: Chainlink working
  });

  it("C1 chainlinkWorking: Chainlink price drop of >50% and Tellor price matches: return Chainlink price", async () => {
    priceFeed.setLastGoodPrice(dec(2, 18));

    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await priceFeed.setLastGoodPrice(dec(2, 18)); // price = 2
    await mockChainlink.setPrice(99999999); // price drops to 0.99999999: a drop of > 50% from previous
    await mockTellor.setPrice(dec(99999999, 10)); // Tellor price drops to same value (at 6 decimals)

    const priceFetchTx = await priceFeed.fetchPrice();
    let price = await priceFeed.lastGoodPrice();
    assert.equal(price, dec(99999999, 10));
  });

  it("C1 chainlinkWorking: Chainlink price drop of >50% and Tellor price within 5% of Chainlink: remain chainlinkWorking", async () => {
    priceFeed.setLastGoodPrice(dec(2, 18));

    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await priceFeed.setLastGoodPrice(dec(1000, 18)); // prev price = 1000
    await mockChainlink.setPrice(dec(100, 8)); // price drops to 100: a drop of > 50% from previous
    await mockTellor.setPrice(dec(104999999, 12)); // Tellor price drops to 104.99: price difference with new Chainlink price is now just under 5%

    const priceFetchTx = await priceFeed.fetchPrice();
    const statusAfter = await priceFeed.status();
    assert.equal(statusAfter, "0"); // status 0: Chainlink working
  });

  it("C1 chainlinkWorking: Chainlink price drop of >50% and Tellor price within 5% of Chainlink: return Chainlink price", async () => {
    priceFeed.setLastGoodPrice(dec(2, 18));

    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await priceFeed.setLastGoodPrice(dec(1000, 18)); // prev price = 1000
    await mockChainlink.setPrice(dec(100, 8)); // price drops to 100: a drop of > 50% from previous
    await mockTellor.setPrice(dec(104999999, 12)); // Tellor price drops to 104.99: price difference with new Chainlink price is now just under 5%

    const priceFetchTx = await priceFeed.fetchPrice();
    let price = await priceFeed.lastGoodPrice();
    assert.equal(price, dec(100, 18));
  });

  it("C1 chainlinkWorking: Chainlink price drop of >50% and Tellor live but not within 5% of Chainlink: switch to usingChainlinkTellorUntrusted", async () => {
    priceFeed.setLastGoodPrice(dec(2, 18));

    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await priceFeed.setLastGoodPrice(dec(1000, 18)); // prev price = 1000
    await mockChainlink.setPrice(dec(100, 8)); // price drops to 100: a drop of > 50% from previous
    await mockTellor.setPrice(dec(105000001, 12)); // Tellor price drops to 105.000001: price difference with new Chainlink price is now > 5%

    const priceFetchTx = await priceFeed.fetchPrice();
    const statusAfter = await priceFeed.status();
    assert.equal(statusAfter, "1"); // status 1: using Tellor, Chainlink untrusted
  });

  it("C1 chainlinkWorking: Chainlink price drop of >50% and Tellor live but not within 5% of Chainlink: return Tellor price", async () => {
    priceFeed.setLastGoodPrice(dec(2, 18));

    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await priceFeed.setLastGoodPrice(dec(1000, 18)); // prev price = 1000
    await mockChainlink.setPrice(dec(100, 8)); // price drops to 100: a drop of > 50% from previous
    await mockTellor.setPrice(dec(105000001, 12)); // Tellor price drops to 105.000001: price difference with new Chainlink price is now > 5%

    const priceFetchTx = await priceFeed.fetchPrice();
    let price = await priceFeed.lastGoodPrice();

    assert.equal(price, dec(105000001, 12)); // return Tellor price
  });

  it("C1 chainlinkWorking: Chainlink price drop of >50% and Tellor frozen: switch to usingChainlinkTellorUntrusted", async () => {
    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await priceFeed.setLastGoodPrice(dec(1000, 18)); // prev price = 1000
    await mockChainlink.setPrice(dec(100, 8)); // price drops to 100: a drop of > 50% from previous
    await mockTellor.setPrice(dec(100, 18));

    // 4 hours pass with no Tellor updates
    await th.fastForwardTime(14400, web3.currentProvider);

    // check Tellor price timestamp is out of date by > 4 hours
    const now = await th.getLatestBlockTimestamp(web3);
    const tellorUpdateTime = await mockTellor.getTimestampbyRequestIDandIndex(0, 0);
    assert.isTrue(tellorUpdateTime.lt(toBN(now).sub(toBN(14400))));

    await mockChainlink.setUpdateTime(now);

    const priceFetchTx = await priceFeed.fetchPrice();

    const statusAfter = await priceFeed.status();
    assert.equal(statusAfter, "1"); // status 1: using Tellor, Chainlink untrusted
  });

  it("C1 chainlinkWorking: Chainlink price drop of >50% and Tellor frozen: return last good price", async () => {
    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await priceFeed.setLastGoodPrice(dec(1000, 18)); // prev price = 1000
    await mockChainlink.setPrice(dec(100, 8)); // price drops to 100: a drop of > 50% from previous
    await mockTellor.setPrice(dec(100, 18));

    // 4 hours pass with no Tellor updates
    await th.fastForwardTime(14400, web3.currentProvider);

    // check Tellor price timestamp is out of date by > 4 hours
    const now = await th.getLatestBlockTimestamp(web3);
    const tellorUpdateTime = await mockTellor.getTimestampbyRequestIDandIndex(0, 0);
    assert.isTrue(tellorUpdateTime.lt(toBN(now).sub(toBN(14400))));

    await mockChainlink.setUpdateTime(now);

    const priceFetchTx = await priceFeed.fetchPrice();
    let price = await priceFeed.lastGoodPrice();

    // Check that the returned price is the last good price
    assert.equal(price, dec(1000, 18));
  });

  // --- Chainlink fails and Tellor is broken ---

  it("C1 chainlinkWorking: Chainlink price drop of >50% and Tellor is broken by 0 price: switch to bothOracleSuspect", async () => {
    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await priceFeed.setLastGoodPrice(dec(2, 18)); // price = 2
    await mockChainlink.setPrice(99999999); // price drops to 0.99999999: a drop of > 50% from previous

    // Make mock Tellor return 0 price
    await mockTellor.setPrice(0);

    const priceFetchTx = await priceFeed.fetchPrice();

    const statusAfter = await priceFeed.status();
    assert.equal(statusAfter, "2"); // status 2: both oracles untrusted
  });

  it("C1 chainlinkWorking: Chainlink price drop of >50% and Tellor is broken by 0 timestamp: switch to bothOracleSuspect", async () => {
    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    // Make mock Chainlink price deviate too much
    await priceFeed.setLastGoodPrice(dec(2, 18)); // price = 2
    await mockChainlink.setPrice(99999999); // price drops to 0.99999999: a drop of > 50% from previous

    // Make mock Tellor return 0 timestamp
    await mockTellor.setUpdateTime(0);
    const priceFetchTx = await priceFeed.fetchPrice();

    const statusAfter = await priceFeed.status();
    assert.equal(statusAfter, "2"); // status 2: both oracles untrusted
  });

  it("C1 chainlinkWorking: Chainlink price drop of >50% and Tellor is broken by future timestamp: Pricefeed switches to bothOracleSuspect", async () => {
    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    // Make mock Chainlink price deviate too much
    await priceFeed.setLastGoodPrice(dec(2, 18)); // price = 2
    await mockChainlink.setPrice(99999999); // price drops to 0.99999999: a drop of > 50% from previous

    // Make mock Tellor return 0 timestamp
    await mockTellor.setUpdateTime(0);

    const priceFetchTx = await priceFeed.fetchPrice();

    const statusAfter = await priceFeed.status();
    assert.equal(statusAfter, "2"); // status 2: both oracles untrusted
  });

  // -- Chainlink is working

  it("C1 chainlinkWorking: Chainlink is working and Tellor is working - remain on chainlinkWorking", async () => {
    priceFeed.setLastGoodPrice(dec(1200, 18));

    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await mockChainlink.setPrice(dec(102, 8));

    await mockTellor.setPrice(dec(103, 18));

    const priceFetchTx = await priceFeed.fetchPrice();

    const statusAfter = await priceFeed.status();
    assert.equal(statusAfter, "0"); // status 0: Chainlink working
  });

  it("C1 chainlinkWorking: Chainlink is working and Tellor is working - return Chainlink price", async () => {
    priceFeed.setLastGoodPrice(dec(1200, 18));

    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await mockChainlink.setPrice(dec(102, 8));

    await mockTellor.setPrice(dec(103, 18));

    const priceFetchTx = await priceFeed.fetchPrice();
    let price = await priceFeed.lastGoodPrice();

    // Check that the returned price is current Chainlink price
    assert.equal(price.toString(), dec(102, 18));
  });

  it("C1 chainlinkWorking: Chainlink is working and Tellor freezes - remain on chainlinkWorking", async () => {
    priceFeed.setLastGoodPrice(dec(200, 18));

    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await mockChainlink.setPrice(dec(102, 8));

    await mockTellor.setPrice(dec(103, 18));

    // 4 hours pass with no Tellor updates
    await th.fastForwardTime(14400, web3.currentProvider);

    // check Tellor price timestamp is out of date by > 4 hours
    const now = await th.getLatestBlockTimestamp(web3);
    const tellorUpdateTime = await mockTellor.getTimestampbyRequestIDandIndex(0, 0);
    assert.isTrue(tellorUpdateTime.lt(toBN(now).sub(toBN(14400))));

    await mockChainlink.setUpdateTime(now); // Chainlink's price is current

    const priceFetchTx = await priceFeed.fetchPrice();

    const statusAfter = await priceFeed.status();
    assert.equal(statusAfter, "0"); // status 0: Chainlink working
  });

  it("C1 chainlinkWorking: Chainlink is working and Tellor freezes - return Chainlink price", async () => {
    priceFeed.setLastGoodPrice(dec(200, 18));

    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await mockChainlink.setPrice(dec(102, 8));

    await mockTellor.setPrice(dec(103, 18));

    // 4 hours pass with no Tellor updates
    await th.fastForwardTime(14400, web3.currentProvider);

    // check Tellor price timestamp is out of date by > 4 hours
    const now = await th.getLatestBlockTimestamp(web3);
    const tellorUpdateTime = await mockTellor.getTimestampbyRequestIDandIndex(0, 0);
    assert.isTrue(tellorUpdateTime.lt(toBN(now).sub(toBN(14400))));

    await mockChainlink.setUpdateTime(now); // Chainlink's price is current

    const priceFetchTx = await priceFeed.fetchPrice();
    let price = await priceFeed.lastGoodPrice();

    // Check that the returned price is current Chainlink price
    assert.equal(price.toString(), dec(102, 18));
  });

  it("C1 chainlinkWorking: Chainlink is working and Tellor breaks: switch to usingChainlinkTellorUntrusted", async () => {
    priceFeed.setLastGoodPrice(dec(200, 18)); // establish a "last good price" from the previous price fetch

    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await mockChainlink.setPrice(dec(102, 8));

    await mockTellor.setPrice(0);

    const priceFetchTx = await priceFeed.fetchPrice();

    const statusAfter = await priceFeed.status();
    assert.equal(statusAfter, "4"); // status 4: Using Tellor, Chainlink untrusted
  });

  it("C1 chainlinkWorking: Chainlink is working and Tellor breaks: return Chainlink price", async () => {
    priceFeed.setLastGoodPrice(dec(200, 18)); // establish a "last good price" from the previous price fetch

    const statusBefore = await priceFeed.status();
    assert.equal(statusBefore, "0"); // status 0: Chainlink working

    await mockChainlink.setPrice(dec(102, 8));

    await mockTellor.setPrice(0);

    const priceFetchTx = await priceFeed.fetchPrice();
    let price = await priceFeed.lastGoodPrice();

    // Check that the returned price is current Chainlink price
    assert.equal(price.toString(), dec(102, 18));
  });

  // --- Case 2: Using Tellor ---

  // Using Tellor, Tellor breaks
  it("C2 usingTellorChainlinkUntrusted: Tellor breaks by zero price: switch to bothOraclesSuspect", async () => {
    priceFeed.setStatus(1); // status 1: using Tellor, Chainlink untrusted

    await mockChainlink.setPrice(dec(999, 8));

    await priceFeed.setLastGoodPrice(dec(123, 18));

    const now = await th.getLatestBlockTimestamp(web3);
    await mockTellor.setUpdateTime(now);
    await mockTellor.setPrice(0);

    await priceFeed.fetchPrice();

    const status = await priceFeed.status();
    assert.equal(status, 2); // status 2: both oracles untrusted
  });

  it("C2 usingTellorChainlinkUntrusted: Tellor breaks by zero price: return last good price", async () => {
    priceFeed.setStatus(1); // status 1: using Tellor, Chainlink untrusted

    await mockChainlink.setPrice(dec(999, 8));

    await priceFeed.setLastGoodPrice(dec(123, 18));

    const now = await th.getLatestBlockTimestamp(web3);
    await mockTellor.setUpdateTime(now);
    await mockTellor.setPrice(0);

    await priceFeed.fetchPrice();
    const price = await priceFeed.lastGoodPrice();

    assert.equal(price.toString(), dec(123, 18));
  });

  // Using Tellor, Tellor breaks
  it("C2 usingTellorChainlinkUntrusted: Tellor breaks by call reverted: switch to bothOraclesSuspect", async () => {
    priceFeed.setStatus(1); // status 1: using Tellor, Chainlink untrusted

    await priceFeed.setLastGoodPrice(dec(123, 18));

    await mockChainlink.setPrice(dec(999, 8));
    await mockTellor.setPrice(dec(999, 18));

    await mockTellor.setRevertRequest();

    await priceFeed.fetchPrice();

    const status = await priceFeed.status();
    assert.equal(status, 2); // status 2: both oracles untrusted
  });

  it("C2 usingTellorChainlinkUntrusted: Tellor breaks by call reverted: return last good price", async () => {
    priceFeed.setStatus(1); // status 1: using Tellor, Chainlink untrusted

    await priceFeed.setLastGoodPrice(dec(123, 18));

    await mockChainlink.setPrice(dec(999, 8));
    await mockTellor.setPrice(dec(999, 18));

    await mockTellor.setRevertRequest();

    await priceFeed.fetchPrice();
    const price = await priceFeed.lastGoodPrice();

    assert.equal(price.toString(), dec(123, 18));
  });

  // Using Tellor, Tellor breaks
  it("C2 usingTellorChainlinkUntrusted: Tellor breaks by zero timestamp: switch to bothOraclesSuspect", async () => {
    priceFeed.setStatus(1); // status 1: using Tellor, Chainlink untrusted

    await priceFeed.setLastGoodPrice(dec(123, 18));

    await mockChainlink.setPrice(dec(999, 8));
    await mockTellor.setPrice(dec(999, 18));

    await mockTellor.setUpdateTime(0);

    await priceFeed.fetchPrice();

    const status = await priceFeed.status();
    assert.equal(status, 2); // status 2: both oracles untrusted
  });

  it("C2 usingTellorChainlinkUntrusted: Tellor breaks by zero timestamp: return last good price", async () => {
    priceFeed.setStatus(1); // status 1: using Tellor, Chainlink untrusted

    await priceFeed.setLastGoodPrice(dec(123, 18));

    await mockChainlink.setPrice(dec(999, 8));
    await mockTellor.setPrice(dec(999, 18));

    await mockTellor.setUpdateTime(0);

    await priceFeed.fetchPrice();
    const price = await priceFeed.lastGoodPrice();

    assert.equal(price.toString(), dec(123, 18));
  });

  // Using Tellor, Tellor freezes
  it("C2 usingTellorChainlinkUntrusted: Tellor freezes - remain usingChainlinkTellorUntrusted", async () => {
    priceFeed.setStatus(1); // status 1: using Tellor, Chainlink untrusted

    await mockChainlink.setPrice(dec(999, 8));

    await priceFeed.setLastGoodPrice(dec(500, 18));

    await mockTellor.setPrice(dec(123, 18));

    await th.fastForwardTime(14400, web3.currentProvider); // Fast forward 4 hours

    // check Tellor price timestamp is out of date by > 4 hours
    const now = await th.getLatestBlockTimestamp(web3);
    const tellorUpdateTime = await mockTellor.getTimestampbyRequestIDandIndex(0, 0);
    assert.isTrue(tellorUpdateTime.lt(toBN(now).sub(toBN(14400))));

    await mockChainlink.setUpdateTime(now);

    await priceFeed.fetchPrice();

    const status = await priceFeed.status();
    assert.equal(status, 1); // status 1: using Tellor, Chainlink untrusted
  });

  it("C2 usingTellorChainlinkUntrusted: Tellor freezes - return last good price", async () => {
    priceFeed.setStatus(1); // status 1: using Tellor, Chainlink untrusted

    await mockChainlink.setPrice(dec(999, 8));

    await priceFeed.setLastGoodPrice(dec(246, 18));

    await mockTellor.setPrice(dec(123, 18));

    await th.fastForwardTime(14400, web3.currentProvider); // Fast forward 4 hours

    // check Tellor price timestamp is out of date by > 4 hours
    const now = await th.getLatestBlockTimestamp(web3);
    const tellorUpdateTime = await mockTellor.getTimestampbyRequestIDandIndex(0, 0);
    assert.isTrue(tellorUpdateTime.lt(toBN(now).sub(toBN(14400))));

    await mockChainlink.setUpdateTime(now);

    await priceFeed.fetchPrice();
    const price = await priceFeed.lastGoodPrice();

    assert.equal(price.toString(), dec(246, 18));
  });

  // Using Tellor, both Chainlink & Tellor go live

  it("C2 usingTellorChainlinkUntrusted: both Tellor and Chainlink are live and <= 5% price difference - switch to chainlinkWorking", async () => {
    priceFeed.setStatus(1); // status 1: using Tellor, Chainlink untrusted

    await mockTellor.setPrice(dec(100, 18)); // price = 100
    await mockChainlink.setPrice(dec(105, 8)); // price = 105: 5% difference from Chainlink

    await priceFeed.fetchPrice();

    const status = await priceFeed.status();
    assert.equal(status, 0); // status 0: Chainlink working
  });

  it("C2 usingTellorChainlinkUntrusted: both Tellor and Chainlink are live and <= 5% price difference - return Chainlink price", async () => {
    priceFeed.setStatus(1); // status 1: using Tellor, Chainlink untrusted

    await mockTellor.setPrice(dec(100, 18)); // price = 100
    await mockChainlink.setPrice(dec(105, 8)); // price = 105: 5% difference from Chainlink

    await priceFeed.fetchPrice();

    const price = await priceFeed.lastGoodPrice();
    assert.equal(price.toString(), dec(105, 18));
  });

  it("C2 usingTellorChainlinkUntrusted: both Tellor and Chainlink are live and > 5% price difference - remain usingChainlinkTellorUntrusted", async () => {
    priceFeed.setStatus(1); // status 1: using Tellor, Chainlink untrusted

    await mockTellor.setPrice(dec(100, 18)); // price = 100
    await mockChainlink.setPrice("10500000001"); // price = 105.00000001: > 5% difference from Tellor

    await priceFeed.fetchPrice();

    const status = await priceFeed.status();
    assert.equal(status, 1); // status 1: using Tellor, Chainlink untrusted
  });

  it("C2 usingTellorChainlinkUntrusted: both Tellor and Chainlink are live and > 5% price difference - return Tellor price", async () => {
    priceFeed.setStatus(1); // status 1: using Tellor, Chainlink untrusted

    await mockTellor.setPrice(dec(100, 18)); // price = 100
    await mockChainlink.setPrice("10500000001"); // price = 105.00000001: > 5% difference from Tellor

    await priceFeed.fetchPrice();

    const price = await priceFeed.lastGoodPrice();
    assert.equal(price.toString(), dec(100, 18));
  });

  // --- Case 3: Both Oracles suspect

  it("C3 bothOraclesUntrusted: both Tellor and Chainlink are live and > 5% price difference remain bothOraclesSuspect", async () => {
    priceFeed.setStatus(2); // status 2: both oracles untrusted

    await priceFeed.setLastGoodPrice(dec(50, 18));

    await mockTellor.setPrice(dec(100, 18)); // price = 100
    await mockChainlink.setPrice("10500000001"); // price = 105.00000001: > 5% difference from Tellor

    const status = await priceFeed.status();
    assert.equal(status, 2); // status 2: both oracles untrusted
  });

  it("C3 bothOraclesUntrusted: both Tellor and Chainlink are live and > 5% price difference, return last good price", async () => {
    priceFeed.setStatus(2); // status 2: both oracles untrusted

    await priceFeed.setLastGoodPrice(dec(50, 18));

    await mockTellor.setPrice(dec(100, 18)); // price = 100
    await mockChainlink.setPrice("10500000001"); // price = 105.00000001: > 5% difference from Tellor

    await priceFeed.fetchPrice();
    const price = await priceFeed.lastGoodPrice();

    assert.equal(price.toString(), dec(50, 18));
  });

  it("C3 bothOraclesUntrusted: both Tellor and Chainlink are live and <= 5% price difference, switch to chainlinkWorking", async () => {
    priceFeed.setStatus(2); // status 2: both oracles untrusted

    await mockTellor.setPrice(dec(100, 18)); // price = 100
    await mockChainlink.setPrice(dec(105, 8)); // price = 105: 5% difference from Tellor

    await priceFeed.fetchPrice();

    const status = await priceFeed.status();
    assert.equal(status, 0); // status 0: Chainlink working
  });

  it("C3 bothOraclesUntrusted: both Tellor and Chainlink are live and <= 5% price difference, return Chainlink price", async () => {
    priceFeed.setStatus(2); // status 2: both oracles untrusted

    await mockTellor.setPrice(dec(100, 18)); // price = 100
    await mockChainlink.setPrice(dec(105, 8)); // price = 105: 5% difference from Tellor

    await priceFeed.fetchPrice();

    const price = await priceFeed.lastGoodPrice();
    assert.equal(price.toString(), dec(105, 18));
  });

  // --- Case 4 ---
  it("C4 usingTellorChainlinkFrozen: when both Chainlink and Tellor break, switch to bothOraclesSuspect", async () => {
    priceFeed.setStatus(3); // status 3: using Tellor, Chainlink frozen

    // Both Chainlink and Tellor break with 0 price
    await mockChainlink.setPrice(0);
    await mockTellor.setPrice(0);

    await priceFeed.fetchPrice();

    const status = await priceFeed.status();
    assert.equal(status, 2); // status 2: both oracles untrusted
  });

  it("C4 usingTellorChainlinkFrozen: when both Chainlink and Tellor break, return last good price", async () => {
    priceFeed.setStatus(2); // status 2: using tellor, chainlink frozen

    await priceFeed.setLastGoodPrice(dec(50, 18));

    // Both Chainlink and Tellor break with 0 price
    await mockChainlink.setPrice(dec(0));
    await mockTellor.setPrice(dec(0));

    await priceFeed.fetchPrice();

    const price = await priceFeed.lastGoodPrice();
    assert.equal(price.toString(), dec(50, 18));
  });

  it("C4 usingTellorChainlinkFrozen: when Chainlink breaks and Tellor freezes, switch to usingChainlinkTellorUntrusted", async () => {
    priceFeed.setStatus(3); // status 3: using Tellor, Chainlink frozen

    await priceFeed.setLastGoodPrice(dec(50, 18));

    // Chainlink breaks
    await mockChainlink.setPrice(dec(0));

    await mockTellor.setPrice(dec(123, 18));

    await th.fastForwardTime(14400, web3.currentProvider); // Fast forward 4 hours

    // check Tellor price timestamp is out of date by > 4 hours
    const now = await th.getLatestBlockTimestamp(web3);
    const tellorUpdateTime = await mockTellor.getTimestampbyRequestIDandIndex(0, 0);
    assert.isTrue(tellorUpdateTime.lt(toBN(now).sub(toBN(14400))));

    await priceFeed.fetchPrice();

    const status = await priceFeed.status();
    assert.equal(status, 1); // status 1: using Tellor, Chainlink untrusted
  });

  it("C4 usingTellorChainlinkFrozen: when Chainlink breaks and Tellor freezes, return last good price", async () => {
    priceFeed.setStatus(3); // status 3: using Tellor, Chainlink frozen

    await priceFeed.setLastGoodPrice(dec(50, 18));

    // Chainlink breaks
    await mockChainlink.setPrice(dec(0));

    await mockTellor.setPrice(dec(123, 18));

    await th.fastForwardTime(14400, web3.currentProvider); // Fast forward 4 hours

    // check Tellor price timestamp is out of date by > 4 hours
    const now = await th.getLatestBlockTimestamp(web3);
    const tellorUpdateTime = await mockTellor.getTimestampbyRequestIDandIndex(0, 0);
    assert.isTrue(tellorUpdateTime.lt(toBN(now).sub(toBN(14400))));

    await priceFeed.fetchPrice();

    const price = await priceFeed.lastGoodPrice();
    assert.equal(price.toString(), dec(50, 18));
  });

  it("C4 usingTellorChainlinkFrozen: when Chainlink breaks and Tellor live, switch to usingChainlinkTellorUntrusted", async () => {
    priceFeed.setStatus(3); // status 3: using Tellor, Chainlink frozen

    await priceFeed.setLastGoodPrice(dec(50, 18));

    // Chainlink breaks
    await mockChainlink.setPrice(dec(0));

    await mockTellor.setPrice(dec(123, 18));

    await th.fastForwardTime(14400, web3.currentProvider); // Fast forward 4 hours

    await priceFeed.fetchPrice();

    const status = await priceFeed.status();
    assert.equal(status, 1); // status 1: using Tellor, Chainlink untrusted
  });

  it("C4 usingTellorChainlinkFrozen: when Chainlink breaks and Tellor live, return Tellor price", async () => {
    priceFeed.setStatus(3); // status 3: using Tellor, Chainlink frozen

    await priceFeed.setLastGoodPrice(dec(50, 18));

    // Chainlink breaks
    await mockChainlink.setPrice(dec(0));

    await mockTellor.setPrice(dec(123, 18));

    await priceFeed.fetchPrice();

    const price = await priceFeed.lastGoodPrice();
    assert.equal(price.toString(), dec(123, 18));
  });

  it("C4 usingTellorChainlinkFrozen: when Chainlink is live and Tellor is live with <5% price difference, switch back to chainlinkWorking", async () => {
    priceFeed.setStatus(3); // status 3: using Tellor, Chainlink frozen

    await priceFeed.setLastGoodPrice(dec(50, 18));

    await mockChainlink.setPrice(dec(999, 8));

    await mockTellor.setPrice(dec(998, 18));

    await priceFeed.fetchPrice();

    const status = await priceFeed.status();
    assert.equal(status, 0); // status 0: Chainlink working
  });

  it("C4 usingTellorChainlinkFrozen: when Chainlink is live and Tellor is live with <5% price difference, return Chainlink current price", async () => {
    priceFeed.setStatus(3); // status 3: using Tellor, Chainlink frozen

    await priceFeed.setLastGoodPrice(dec(50, 18));

    await mockChainlink.setPrice(dec(999, 8));

    await mockTellor.setPrice(dec(998, 18));

    await priceFeed.fetchPrice();

    const price = await priceFeed.lastGoodPrice();
    assert.equal(price.toString(), dec(999, 18)); // Chainlink price
  });

  it("C4 usingTellorChainlinkFrozen: when Chainlink is live and Tellor is live with >5% price difference, switch back to usingChainlinkTellorUntrusted", async () => {
    priceFeed.setStatus(3); // status 3: using Tellor, Chainlink frozen

    await priceFeed.setLastGoodPrice(dec(50, 18));

    await mockChainlink.setPrice(dec(999, 8));

    await mockTellor.setPrice(dec(123, 18));

    await priceFeed.fetchPrice();

    const status = await priceFeed.status();
    assert.equal(status, 1); // status 1: Using Tellor, Chainlink untrusted
  });

  it("C4 usingTellorChainlinkFrozen: when Chainlink is live and Tellor is live with >5% price difference, return Chainlink current price", async () => {
    priceFeed.setStatus(3); // status 3: using Tellor, Chainlink frozen

    await priceFeed.setLastGoodPrice(dec(50, 18));

    await mockChainlink.setPrice(dec(999, 8));

    await mockTellor.setPrice(dec(123, 18));

    await priceFeed.fetchPrice();

    const price = await priceFeed.lastGoodPrice();
    assert.equal(price.toString(), dec(123, 18)); // Tellor price
  });

  it("C4 usingTellorChainlinkFrozen: when Chainlink is live and Tellor is live with similar price, switch back to chainlinkWorking", async () => {
    priceFeed.setStatus(3); // status 3: using Tellor, Chainlink frozen

    await priceFeed.setLastGoodPrice(dec(50, 18));

    await mockChainlink.setPrice(dec(999, 8));

    await mockTellor.setPrice(dec(998, 18));

    await priceFeed.fetchPrice();

    const status = await priceFeed.status();
    assert.equal(status, 0); // status 0: Chainlink working
  });

  it("C4 usingTellorChainlinkFrozen: when Chainlink is live and Tellor is live with similar price, return Chainlink current price", async () => {
    priceFeed.setStatus(3); // status 3: using Tellor, Chainlink frozen

    await priceFeed.setLastGoodPrice(dec(50, 18));

    await mockChainlink.setPrice(dec(999, 8));

    await mockTellor.setPrice(dec(998, 18));

    await priceFeed.fetchPrice();

    const price = await priceFeed.lastGoodPrice();
    assert.equal(price.toString(), dec(999, 18)); // Chainlink price
  });

  it("C4 usingTellorChainlinkFrozen: when Chainlink is live and Tellor breaks, switch to usingChainlinkTellorUntrusted", async () => {
    priceFeed.setStatus(3); // status 3: using Tellor, Chainlink frozen

    await priceFeed.setLastGoodPrice(dec(50, 18));

    await mockChainlink.setPrice(dec(999, 8));

    await mockTellor.setPrice(0);

    await priceFeed.fetchPrice();

    const status = await priceFeed.status();
    assert.equal(status, 4); // status 4: Using Chainlink, Tellor untrusted
  });

  it("C4 usingTellorChainlinkFrozen: when Chainlink is live and Tellor breaks, return Chainlink current price", async () => {
    priceFeed.setStatus(3); // status 3: using Tellor, Chainlink frozen

    await priceFeed.setLastGoodPrice(dec(50, 18));

    await mockChainlink.setPrice(dec(999, 8));

    await mockTellor.setPrice(0);

    await priceFeed.fetchPrice();

    const price = await priceFeed.lastGoodPrice();
    assert.equal(price.toString(), dec(999, 18));
  });

  it("C4 usingTellorChainlinkFrozen: when Chainlink still frozen and Tellor breaks, switch to usingChainlinkTellorUntrusted", async () => {
    priceFeed.setStatus(3); // status 3: using Tellor, Chainlink frozen

    await priceFeed.setLastGoodPrice(dec(50, 18));

    await mockChainlink.setPrice(dec(999, 8));

    await th.fastForwardTime(14400, web3.currentProvider); // Fast forward 4 hours

    // check Chainlink price timestamp is out of date by > 4 hours
    const now = await th.getLatestBlockTimestamp(web3);
    const chainlinkUpdateTime = (await mockChainlink.latestRoundData())[3];
    assert.isTrue(chainlinkUpdateTime.lt(toBN(now).sub(toBN(14400))));

    // set tellor broken
    await mockTellor.setPrice(0);
    await mockTellor.set;

    await priceFeed.fetchPrice();

    const status = await priceFeed.status();
    assert.equal(status, 4); // status 4: using Chainlink, Tellor untrusted
  });

  it("C4 usingTellorChainlinkFrozen: when Chainlink still frozen and Tellor broken, return last good price", async () => {
    priceFeed.setStatus(3); // status 3: using Tellor, Chainlink frozen

    await priceFeed.setLastGoodPrice(dec(50, 18));

    await mockChainlink.setPrice(dec(999, 8));

    await th.fastForwardTime(14400, web3.currentProvider); // Fast forward 4 hours

    // check Chainlink price timestamp is out of date by > 4 hours
    const now = await th.getLatestBlockTimestamp(web3);
    const chainlinkUpdateTime = (await mockChainlink.latestRoundData())[3];
    assert.isTrue(chainlinkUpdateTime.lt(toBN(now).sub(toBN(14400))));

    // set tellor broken
    await mockTellor.setPrice(0);

    await priceFeed.fetchPrice();

    const price = await priceFeed.lastGoodPrice();
    assert.equal(price.toString(), dec(50, 18));
  });

  it("C4 usingTellorChainlinkFrozen: when Chainlink still frozen and Tellor live, remain usingTellorChainlinkFrozen", async () => {
    priceFeed.setStatus(3); // status 3: using Tellor, Chainlink frozen

    await priceFeed.setLastGoodPrice(dec(50, 18));

    await mockChainlink.setPrice(dec(999, 8));

    await mockTellor.setPrice(dec(123, 18));

    await th.fastForwardTime(14400, web3.currentProvider); // Fast forward 4 hours

    // check Chainlink price timestamp is out of date by > 4 hours
    const now = await th.getLatestBlockTimestamp(web3);
    const chainlinkUpdateTime = (await mockChainlink.latestRoundData())[3];
    assert.isTrue(chainlinkUpdateTime.lt(toBN(now).sub(toBN(14400))));

    // set Tellor to current time
    await mockTellor.setUpdateTime(now);

    await priceFeed.fetchPrice();

    const status = await priceFeed.status();
    assert.equal(status, 3); // status 3: using Tellor, Chainlink frozen
  });

  it("C4 usingTellorChainlinkFrozen: when Chainlink still frozen and Tellor live, return Tellor price", async () => {
    priceFeed.setStatus(3); // status 3: using Tellor, Chainlink frozen

    await priceFeed.setLastGoodPrice(dec(50, 18));

    await mockChainlink.setPrice(dec(999, 8));

    await mockTellor.setPrice(dec(123, 18));

    await th.fastForwardTime(14400, web3.currentProvider); // Fast forward 4 hours

    // check Chainlink price timestamp is out of date by > 4 hours
    const now = await th.getLatestBlockTimestamp(web3);
    const chainlinkUpdateTime = (await mockChainlink.latestRoundData())[3];
    assert.isTrue(chainlinkUpdateTime.lt(toBN(now).sub(toBN(14400))));

    // set Tellor to current time
    await mockTellor.setUpdateTime(now);

    await priceFeed.fetchPrice();

    const price = await priceFeed.lastGoodPrice();
    assert.equal(price.toString(), dec(123, 18));
  });

  it("C4 usingTellorChainlinkFrozen: when Chainlink still frozen and Tellor freezes, remain usingTellorChainlinkFrozen", async () => {
    priceFeed.setStatus(3); // status 3: using Tellor, Chainlink frozen

    await priceFeed.setLastGoodPrice(dec(50, 18));

    await mockChainlink.setPrice(dec(999, 8));

    await mockTellor.setPrice(dec(123, 18));

    await th.fastForwardTime(14400, web3.currentProvider); // Fast forward 4 hours

    // check Chainlink price timestamp is out of date by > 4 hours
    const now = await th.getLatestBlockTimestamp(web3);
    const chainlinkUpdateTime = (await mockChainlink.latestRoundData())[3];
    assert.isTrue(chainlinkUpdateTime.lt(toBN(now).sub(toBN(14400))));

    // check Tellor price timestamp is out of date by > 4 hours
    const tellorUpdateTime = await mockTellor.getTimestampbyRequestIDandIndex(0, 0);
    assert.isTrue(tellorUpdateTime.lt(toBN(now).sub(toBN(14400))));

    await priceFeed.fetchPrice();

    const status = await priceFeed.status();
    assert.equal(status, 3); // status 3: using Tellor, Chainlink frozen
  });

  it("C4 usingTellorChainlinkFrozen: when Chainlink still frozen and Tellor freezes, return last good price", async () => {
    priceFeed.setStatus(3); // status 3: using Tellor, Chainlink frozen

    await priceFeed.setLastGoodPrice(dec(50, 18));

    await mockChainlink.setPrice(dec(999, 8));

    await mockTellor.setPrice(dec(123, 18));

    await th.fastForwardTime(14400, web3.currentProvider); // Fast forward 4 hours

    // check Chainlink price timestamp is out of date by > 4 hours
    const now = await th.getLatestBlockTimestamp(web3);
    const chainlinkUpdateTime = (await mockChainlink.latestRoundData())[3];
    assert.isTrue(chainlinkUpdateTime.lt(toBN(now).sub(toBN(14400))));

    // check Tellor price timestamp is out of date by > 4 hours
    const tellorUpdateTime = await mockTellor.getTimestampbyRequestIDandIndex(0, 0);
    assert.isTrue(tellorUpdateTime.lt(toBN(now).sub(toBN(14400))));

    await priceFeed.fetchPrice();

    const price = await priceFeed.lastGoodPrice();
    assert.equal(price.toString(), dec(50, 18));
  });

  // --- Case 5 ---
  it("C5 usingChainlinkTellorUntrusted: when Chainlink is live and Tellor price >5% - no status change", async () => {
    priceFeed.setStatus(4); // status 4: using chainlink, Tellor untrusted

    await priceFeed.setLastGoodPrice(dec(500, 18));

    await mockChainlink.setPrice(dec(999, 8));

    await mockTellor.setPrice(dec(123, 18)); // Greater than 5% difference with chainlink

    await priceFeed.fetchPrice();

    const status = await priceFeed.status();
    assert.equal(status, 4); // status 4: using Chainlink, Tellor untrusted
  });

  it("C5 usingChainlinkTellorUntrusted: when Chainlink is live and Tellor price >5% - return Chainlink price", async () => {
    priceFeed.setStatus(4); // status 4: using chainlink, Tellor untrusted

    await priceFeed.setLastGoodPrice(dec(500, 18));

    await mockChainlink.setPrice(dec(999, 8));

    await mockTellor.setPrice(dec(123, 18)); // Greater than 5% difference with chainlink

    await priceFeed.fetchPrice();

    const price = await priceFeed.lastGoodPrice();
    assert.equal(price.toString(), dec(999, 18));
  });

  it("C5 usingChainlinkTellorUntrusted: when Chainlink is live and Tellor price within <5%, switch to chainlinkWorking", async () => {
    priceFeed.setStatus(4); // status 4:  using chainlink, Tellor untrusted

    await priceFeed.setLastGoodPrice(dec(500, 18));

    await mockChainlink.setPrice(dec(999, 8));

    await mockTellor.setPrice(dec(998, 18)); // within 5% of Chainlink

    await priceFeed.fetchPrice();

    const status = await priceFeed.status();
    assert.equal(status, 0); // status 0: Chainlink working
  });

  it("C5 usingChainlinkTellorUntrusted: when Chainlink is live, Tellor price not within 5%, return Chainlink price", async () => {
    priceFeed.setStatus(4); // status 4:  using chainlink, Tellor untrusted

    await priceFeed.setLastGoodPrice(dec(500, 18));

    await mockChainlink.setPrice(dec(999, 8));

    await mockTellor.setPrice(dec(998, 18)); // within 5% of Chainlink

    await priceFeed.fetchPrice();

    const price = await priceFeed.lastGoodPrice();
    assert.equal(price.toString(), dec(999, 18));
  });

  // ---------

  it("C5 usingChainlinkTellorUntrusted: when Chainlink is live, <50% price deviation from previous, Tellor price not within 5%, remain on usingChainlinkTellorUntrusted", async () => {
    priceFeed.setStatus(4); // status 4:  using chainlink, Tellor untrusted

    await priceFeed.setLastGoodPrice(dec(500, 18));

    await mockChainlink.setPrice(dec(998, 8));
    await mockTellor.setPrice(dec(123, 18)); // Tellor not close to current Chainlink

    await priceFeed.fetchPrice();

    const status = await priceFeed.status();
    assert.equal(status, 4); // status 4: using Chainlink, Tellor untrusted
  });

  it("C5 usingChainlinkTellorUntrusted: when Chainlink is live, <50% price deviation from previous, Tellor price not within 5%, return Chainlink price", async () => {
    priceFeed.setStatus(4); // status 4:  using chainlink, Tellor untrusted

    await priceFeed.setLastGoodPrice(dec(500, 18));

    await mockChainlink.setPrice(dec(998, 8));
    await mockTellor.setPrice(dec(123, 18)); // Tellor not close to current Chainlink

    await priceFeed.fetchPrice();

    const price = await priceFeed.lastGoodPrice();
    assert.equal(price.toString(), dec(998, 18));
  });

  it("C5 usingChainlinkTellorUntrusted: when Chainlink is live, <50% price deviation from previous, and Tellor is frozen, remain on usingChainlinkTellorUntrusted", async () => {
    priceFeed.setStatus(4); // status 4:  using chainlink, Tellor untrusted

    await priceFeed.setLastGoodPrice(dec(500, 18));

    await mockChainlink.setPrice(dec(999, 8));

    await mockTellor.setPrice(dec(123, 18));

    await th.fastForwardTime(14400, web3.currentProvider); // fast forward 4 hours

    // check Tellor price timestamp is out of date by > 4 hours
    const now = await th.getLatestBlockTimestamp(web3);
    const tellorUpdateTime = await mockTellor.getTimestampbyRequestIDandIndex(0, 0);
    assert.isTrue(tellorUpdateTime.lt(toBN(now).sub(toBN(14400))));

    await mockChainlink.setPrice(dec(998, 8));
    await mockChainlink.setUpdateTime(now); // Chainlink is current

    await priceFeed.fetchPrice();

    const status = await priceFeed.status();
    assert.equal(status, 4); // status 4: using Chainlink, Tellor untrusted
  });

  it("C5 usingChainlinkTellorUntrusted: when Chainlink is live, <50% price deviation from previous, Tellor is frozen, return Chainlink price", async () => {
    priceFeed.setStatus(4); // status 4:  using chainlink, Tellor untrusted

    await priceFeed.setLastGoodPrice(dec(500, 18));

    await mockChainlink.setPrice(dec(999, 8));

    await mockTellor.setPrice(dec(123, 18));

    await th.fastForwardTime(14400, web3.currentProvider); // fast forward 4 hours

    // check Tellor price timestamp is out of date by > 4 hours
    const now = await th.getLatestBlockTimestamp(web3);
    const tellorUpdateTime = await mockTellor.getTimestampbyRequestIDandIndex(0, 0);
    assert.isTrue(tellorUpdateTime.lt(toBN(now).sub(toBN(14400))));

    await mockChainlink.setPrice(dec(998, 8));
    await mockChainlink.setUpdateTime(now); // Chainlink is current

    await priceFeed.fetchPrice();

    const price = await priceFeed.lastGoodPrice();
    assert.equal(price.toString(), dec(998, 18));
  });

  it("C5 usingChainlinkTellorUntrusted: when Chainlink frozen, remain on usingChainlinkTellorUntrusted", async () => {
    priceFeed.setStatus(4); // status 4: using chainlink, Tellor untrusted

    await priceFeed.setLastGoodPrice(dec(500, 18));

    await mockChainlink.setPrice(dec(999, 8));

    await mockTellor.setPrice(dec(123, 18));

    await th.fastForwardTime(14400, web3.currentProvider); // Fast forward 4 hours

    // check Chainlink price timestamp is out of date by > 4 hours
    const now = await th.getLatestBlockTimestamp(web3);
    const chainlinkUpdateTime = (await mockChainlink.latestRoundData())[3];
    assert.isTrue(chainlinkUpdateTime.lt(toBN(now).sub(toBN(14400))));

    await priceFeed.fetchPrice();

    const status = await priceFeed.status();
    assert.equal(status, 4); // status 4: using Chainlink, Tellor untrusted
  });

  it("C5 usingChainlinkTellorUntrusted: when Chainlink frozen, return last good price", async () => {
    priceFeed.setStatus(4); // status 4: using Chainlink, Tellor untrusted

    await priceFeed.setLastGoodPrice(dec(246, 18));

    await mockChainlink.setPrice(dec(999, 8));

    await mockTellor.setPrice(dec(123, 18));

    await th.fastForwardTime(14400, web3.currentProvider); // Fast forward 4 hours

    // check Chainlink price timestamp is out of date by > 4 hours
    const now = await th.getLatestBlockTimestamp(web3);
    const chainlinkUpdateTime = (await mockChainlink.latestRoundData())[3];
    assert.isTrue(chainlinkUpdateTime.lt(toBN(now).sub(toBN(14400))));

    await priceFeed.fetchPrice();

    const price = await priceFeed.lastGoodPrice();
    assert.equal(price.toString(), dec(246, 18));
  });

  it("C5 usingChainlinkTellorUntrusted: when Chainlink breaks too, switch to bothOraclesSuspect", async () => {
    priceFeed.setStatus(4); // status 4: using chainlink, Tellor untrusted

    await priceFeed.setLastGoodPrice(dec(500, 18));

    await mockChainlink.setPrice(dec(999, 8));
    await mockChainlink.setUpdateTime(0); // Chainlink breaks by 0 timestamp

    await mockTellor.setPrice(dec(123, 18));

    await priceFeed.fetchPrice();

    const status = await priceFeed.status();
    assert.equal(status, 2); // status 2: both oracles untrusted
  });

  it("C5 usingChainlinkTellorUntrusted: Chainlink breaks too, return last good price", async () => {
    priceFeed.setStatus(4); // status 4: using chainlink, Tellor untrusted

    await priceFeed.setLastGoodPrice(dec(246, 18));

    await mockChainlink.setPrice(dec(999, 8));
    await mockChainlink.setUpdateTime(0); // Chainlink breaks by 0 timestamp

    await mockTellor.setPrice(dec(123, 18));

    await priceFeed.fetchPrice();

    const price = await priceFeed.lastGoodPrice();
    assert.equal(price.toString(), dec(246, 18));
  });

  // --- lastGoodPrice timeout tests ---

  it("lastGoodPrice timeout: should revert when both oracles are broken and lastGoodPrice is too old", async () => {
    // Set initial good price
    await mockChainlink.setPrice(dec(100, 8));
    await mockTellor.setPrice(dec(100, 18));
    await priceFeed.fetchPrice();

    const price1 = await priceFeed.lastGoodPrice();
    assert.equal(price1.toString(), dec(100, 18));

    // Fast forward past LAST_GOOD_PRICE_TIMEOUT (24 hours + 1 second)
    await th.fastForwardTime(86401, web3.currentProvider);

    // Break both oracles
    await mockChainlink.setUpdateTime(0);
    await mockTellor.setUpdateTime(0);

    // fetchPrice should revert because lastGoodPrice is too old
    await assertRevert(priceFeed.fetchPrice(), "PriceFeed: lastGoodPrice is too old");
  });

  it("lastGoodPrice timeout: should not revert when both oracles are frozen but within LAST_GOOD_PRICE_TIMEOUT", async () => {
    priceFeed.setStatus(0); // status 0: chainlinkWorking

    // Set initial good price
    await mockChainlink.setPrice(dec(100, 8));
    await mockTellor.setPrice(dec(100, 18));
    await priceFeed.fetchPrice();

    // Fast forward past oracle TIMEOUT (4 hours) but within LAST_GOOD_PRICE_TIMEOUT (24 hours)
    await th.fastForwardTime(14401, web3.currentProvider);

    // Both oracles are frozen but lastGoodPrice is still valid
    // fetchPrice should succeed and return lastGoodPrice
    await priceFeed.fetchPrice();
    const price = await priceFeed.lastGoodPrice();
    assert.equal(price.toString(), dec(100, 18));
  });

  it("lastGoodPrice timeout: should revert when both oracles broken and past LAST_GOOD_PRICE_TIMEOUT", async () => {
    priceFeed.setStatus(1); // status 1: usingTellorChainlinkUntrusted

    // Set initial good price
    await mockTellor.setPrice(dec(100, 18));
    await priceFeed.fetchPrice();

    // Fast forward past LAST_GOOD_PRICE_TIMEOUT (24 hours + 1 second)
    await th.fastForwardTime(86401, web3.currentProvider);

    // Break both oracles
    await mockChainlink.setUpdateTime(0);
    await mockTellor.setUpdateTime(0);

    // fetchPrice should revert because lastGoodPrice is too old
    await assertRevert(priceFeed.fetchPrice(), "PriceFeed: lastGoodPrice is too old");
  });

  it("lastGoodPrice timeout: should return price when both oracles work even if lastGoodPrice is old", async () => {
    // Set initial good price
    await mockChainlink.setPrice(dec(100, 8));
    await mockTellor.setPrice(dec(100, 18));
    await priceFeed.fetchPrice();

    // Fast forward past LAST_GOOD_PRICE_TIMEOUT
    await th.fastForwardTime(86401, web3.currentProvider);

    // Update both oracles with new timestamps and prices
    const now = await th.getLatestBlockTimestamp(web3);
    await mockChainlink.setPrice(dec(150, 8));
    await mockChainlink.setUpdateTime(now);
    await mockTellor.setPrice(dec(150, 18));
    await mockTellor.setUpdateTime(now);

    // fetchPrice should succeed and return new price (lastGoodPrice age doesn't matter when oracles work)
    await priceFeed.fetchPrice();
    const price = await priceFeed.lastGoodPrice();
    assert.equal(price.toString(), dec(150, 18));
  });

  it("lastGoodPrice timeout: should not revert when lastGoodPrice is within LAST_GOOD_PRICE_TIMEOUT", async () => {
    priceFeed.setStatus(2); // status 2: bothOraclesUntrusted

    // Set initial good price
    await mockChainlink.setPrice(dec(100, 8));
    await mockTellor.setPrice(dec(100, 18));
    await priceFeed.fetchPrice();

    // Fast forward less than LAST_GOOD_PRICE_TIMEOUT (12 hours)
    await th.fastForwardTime(43200, web3.currentProvider);

    // Break both oracles
    await mockChainlink.setUpdateTime(0);
    await mockTellor.setUpdateTime(0);

    // fetchPrice should succeed and return lastGoodPrice
    await priceFeed.fetchPrice();
    const price = await priceFeed.lastGoodPrice();
    assert.equal(price.toString(), dec(100, 18));
  });

  it("lastGoodPrice timeout: should update lastGoodPriceTimestamp when storing new price", async () => {
    // Set initial good price
    await mockChainlink.setPrice(dec(100, 8));
    await mockTellor.setPrice(dec(100, 18));

    const timestamp1 = await priceFeed.lastGoodPriceTimestamp();

    await priceFeed.fetchPrice();

    const timestamp2 = await priceFeed.lastGoodPriceTimestamp();

    // Timestamp should be updated
    assert.isTrue(timestamp2.gt(timestamp1));

    // Fast forward 1 hour
    await th.fastForwardTime(3600, web3.currentProvider);

    // Update price again
    const now = await th.getLatestBlockTimestamp(web3);
    await mockChainlink.setPrice(dec(200, 8));
    await mockChainlink.setUpdateTime(now);
    await mockTellor.setPrice(dec(200, 18));
    await mockTellor.setUpdateTime(now);

    await priceFeed.fetchPrice();

    const timestamp3 = await priceFeed.lastGoodPriceTimestamp();

    // Timestamp should be updated again
    assert.isTrue(timestamp3.gt(timestamp2));
  });
});
