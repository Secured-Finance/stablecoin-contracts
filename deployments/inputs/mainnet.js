const { TestHelper: th } = require("../../utils/testHelpers.js");
const dec = th.dec;

const externalAddrs = {
  // https://docs.tellor.io/tellor/the-basics/contracts-reference#mainnet-3
  TELLOR_MASTER: "0x8cFc184c877154a8F9ffE0fe75649dbe5e2DBEbf",
  // https://docs.pyth.network/price-feeds/contract-addresses/evm
  PYTH_PRICE_FEED: "0xA2aa501b19aff244D90cc15a4Cf739D2725B5729",
  PYTH_PRICE_ID: "0x150ac9b959aee0051e4091f0ef5216d941f590e1c5e7f91cf7635b5c11628c0e",
  // https://github.com/sushiswap/v2-core/tree/master/deployments/filecoin
  UNISWAP_V2_FACTORY: "0x9B3336186a38E1b6c21955d112dbb0343Ee061eE",
  UNISWAP_V2_ROUTER02: "0x46B3fDF7b5CDe91Ac049936bF0bDb12c5d22202e",
  // https://filfox.info/en/address/0x60E1773636CF5E4A227d9AC24F20fEca034ee25A
  WRAPPED_NATIVE_TOKEN: "0x60E1773636CF5E4A227d9AC24F20fEca034ee25A",
};

const walletAddrs = {
  FOUNDATION: "0xB260981D89205005cB42A54a4c6D1D19AA73d442",
  DEPLOYER: "0x4F122d7FCE7971E38801aF5d96fcD4ed83EFD654",
  MULTISIG: "0x874AEd75aB58Ba84d5008cfcBf9b9c7B5Eb17d57",
};

const allocationAmounts = {
  FOUNDATION: dec(500_000_000, 18),
};

const annualAllocationSettings = {
  RATE: dec(4, 16), // 4%
  RECIPIENT: walletAddrs.FOUNDATION,
};

// Beneficiaries for lockup contracts.
const beneficiaries = {};

const GAS_COMPENSATION = dec(20, 18); // 20 USDFC
const MIN_NET_DEBT = dec(200, 18); // 200 USDFC
const BOOTSTRAP_PERIOD = 2 * 7 * 24 * 60 * 60; // 2 weeks
const PRICE_FEED_TIMEOUT = 24 * 60 * 60; // 1 day

module.exports = {
  externalAddrs,
  walletAddrs,
  allocationAmounts,
  annualAllocationSettings,
  beneficiaries,
  GAS_COMPENSATION,
  MIN_NET_DEBT,
  BOOTSTRAP_PERIOD,
  PRICE_FEED_TIMEOUT,
};
