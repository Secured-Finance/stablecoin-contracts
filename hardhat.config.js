require("@nomiclabs/hardhat-truffle5");
require("@nomiclabs/hardhat-ethers");
require("@openzeppelin/hardhat-upgrades");
require("solidity-coverage");
require("hardhat-gas-reporter");
require("dotenv").config();

require("./tasks/verify-blockscout.js");
require("./tasks/verify-filfox.js");
require("./tasks/verify-starboard.js");

const accounts = [
  process.env.DEPLOYER_PRIVATEKEY ||
    "0x60ddfe7f579ab6867cbe7a2dc03853dc141d7a4ab6dbefc0dae2d2b1bd4e487f",
];
const testAccounts = require("./accountsList.js");
const testAccountsList = testAccounts.accountsList;
const rpcEndpoint = process.env.RPC_ENDPOINT || "";

module.exports = {
  paths: {
    // contracts: "./contracts",
    // artifacts: "./artifacts"
  },
  solidity: {
    compilers: [
      {
        version: "0.4.23",
        settings: {
          optimizer: {
            enabled: true,
            runs: 100,
          },
        },
      },
      {
        version: "0.7.6",
        settings: {
          optimizer: {
            enabled: true,
            runs: 100,
          },
        },
      },
    ],
  },
  networks: {
    hardhat: {
      accounts: testAccountsList,
      gas: 10000000, // tx gas limit
      blockGasLimit: 15000000,
      gasPrice: 20000000000,
      initialBaseFeePerGas: 0,
      allowUnlimitedContractSize: true,
    },
    localhost: {
      url: "http://127.0.0.1:8545",
      chainId: 31337,
      accounts,
    },
    mainnet: {
      url: rpcEndpoint,
      gasPrice: process.env.GAS_PRICE ? parseInt(process.env.GAS_PRICE) : "auto",
      accounts,
    },
    testnet: {
      url: rpcEndpoint,
      accounts,
    },
  },
  mocha: { timeout: 12000000 },
  rpc: {
    host: "localhost",
    port: 8545,
  },
  gasReporter: {
    enabled: process.env.REPORT_GAS ? true : false,
  },
};
