const { TestHelper: th } = require("../../utils/testHelpers.js");
const dec = th.dec;

const externalAddrs = {
  // https://docs.tellor.io/tellor/the-basics/contracts-reference#calibration
  TELLOR_MASTER: "0xb2CB696fE5244fB9004877e58dcB680cB86Ba444",
  // https://docs.pyth.network/price-feeds/contract-addresses/evm
  PYTH_PRICE_FEED: "0xA2aa501b19aff244D90cc15a4Cf739D2725B5729",
  PYTH_PRICE_ID: "0x150ac9b959aee0051e4091f0ef5216d941f590e1c5e7f91cf7635b5c11628c0e",
  // https://github.com/sushiswap/v2-core/tree/master/deployments/filecoin
  UNISWAP_V2_FACTORY: undefined,
  UNISWAP_V2_ROUTER02: undefined,
  // https://calibration.filfox.info/en/address/0xaC26a4Ab9cF2A8c5DBaB6fb4351ec0F4b07356c4
  WRAPPED_NATIVE_TOKEN: "0xaC26a4Ab9cF2A8c5DBaB6fb4351ec0F4b07356c4",
};

const walletAddrs = {
  FOUNDATION: "0xB260981D89205005cB42A54a4c6D1D19AA73d442",
  DEPLOYER: "0xDBA767F3DFF3835BEf5dE1eDEe91A9901402AB21",
  MULTISIG: "0x15Cd07428b06b6313c2A2212b9Bc6c417A878933",
};

const allocationAmounts = {
  FOUNDATION: dec(500_000_000, 18),
};

const annualAllocationSettings = {
  RATE: dec(4, 16), // 4%
  RECIPIENT: walletAddrs.FOUNDATION,
};

const beneficiaries = {
  TEST_INVESTOR_A: "0xdad05aa3bd5a4904eb2a9482757be5da8d554b3d",
  TEST_INVESTOR_B: "0x625b473f33b37058bf8b9d4c3d3f9ab5b896996a",
  TEST_INVESTOR_C: "0x9ea530178b9660d0fae34a41a02ec949e209142e",
  TEST_INVESTOR_D: "0xffbb4f4b113b05597298b9d8a7d79e6629e726e8",
  TEST_INVESTOR_E: "0x89ff871dbcd0a456fe92db98d190c38bc10d1cc1",
};

const GAS_COMPENSATION = dec(20, 18); // 20 USDFC
const MIN_NET_DEBT = dec(200, 18); // 200 USDFC
const BOOTSTRAP_PERIOD = 24 * 60 * 60; // 1 day
const ORACLE_TIMEOUT = 24 * 60 * 60; // 1 day
const LAST_GOOD_PRICE_TIMEOUT = 3 * 24 * 60 * 60; // 3 days

module.exports = {
  externalAddrs,
  walletAddrs,
  allocationAmounts,
  annualAllocationSettings,
  beneficiaries,
  GAS_COMPENSATION,
  MIN_NET_DEBT,
  BOOTSTRAP_PERIOD,
  ORACLE_TIMEOUT,
  LAST_GOOD_PRICE_TIMEOUT,
};
