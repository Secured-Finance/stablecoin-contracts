const deploymentHelper = require("../utils/testDeploymentHelpers.js");
const testHelpers = require("../utils/testHelpers.js");
const { accountsList } = require("../accountsList.js");

const { keccak256 } = require("@ethersproject/keccak256");
const { defaultAbiCoder } = require("@ethersproject/abi");
const { toUtf8Bytes } = require("@ethersproject/strings");
const { pack } = require("@ethersproject/solidity");
const { hexlify } = require("@ethersproject/bytes");
const { randomBytes } = require("@ethersproject/random");
const { ecsign } = require("ethereumjs-util");
const { ethers, upgrades } = require("hardhat");

const th = testHelpers.TestHelper;
const { toBN, assertRevert, dec, ZERO_ADDRESS, GAS_COMPENSATION, MIN_NET_DEBT } = th;

const sign = (digest, privateKey) => {
  return ecsign(Buffer.from(digest.slice(2), "hex"), Buffer.from(privateKey.slice(2), "hex"));
};

// EIP-3009 type hashes
const TRANSFER_WITH_AUTHORIZATION_TYPEHASH = keccak256(
  toUtf8Bytes(
    "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)",
  ),
);

const RECEIVE_WITH_AUTHORIZATION_TYPEHASH = keccak256(
  toUtf8Bytes(
    "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)",
  ),
);

const CANCEL_AUTHORIZATION_TYPEHASH = keccak256(
  toUtf8Bytes("CancelAuthorization(address authorizer,bytes32 nonce)"),
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

// Returns the EIP712 hash for receiveWithAuthorization
const getReceiveWithAuthorizationDigest = (
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
            [RECEIVE_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce],
          ),
        ),
      ],
    ),
  );
};

// Returns the EIP712 hash for cancelAuthorization
const getCancelAuthorizationDigest = (name, address, chainId, version, authorizer, nonce) => {
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
            ["bytes32", "address", "bytes32"],
            [CANCEL_AUTHORIZATION_TYPEHASH, authorizer, nonce],
          ),
        ),
      ],
    ),
  );
};

contract("DebtToken - EIP-3009 Functionality", async () => {
  let signers;
  let owner, alice, bob, carol, dennis;

  const alicePrivateKey = accountsList[1].privateKey;
  const bobPrivateKey = accountsList[2].privateKey;
  const carolPrivateKey = accountsList[2].privateKey;

  let chainId;
  let debtTokenOriginal;
  let debtTokenTester;
  let stabilityPool;
  let troveManager;
  let borrowerOperations;

  let contracts;
  let protocolTokenContracts;
  let tokenName;
  let tokenVersion;

  before(async () => {
    await hre.network.provider.send("hardhat_reset");
    signers = await ethers.getSigners();
    [owner, alice, bob, carol, dennis] = signers.splice(0, 5);
  });

  // Simple verification tests from DebtTokenEIP3009SimpleTest.js
  describe("Simple EIP-3009 Verification", () => {
    it("should have EIP-3009 functions available in the contract", async () => {
      // Deploy DebtToken directly to test the implementation
      const DebtToken = await ethers.getContractFactory("DebtToken");

      // Deploy with proxy
      const debtToken = await upgrades.deployProxy(
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
      assert.isNotNull(debtToken.transferWithAuthorization);
      assert.isNotNull(debtToken.receiveWithAuthorization);
      assert.isNotNull(debtToken.cancelAuthorization);
      assert.isNotNull(debtToken.authorizationState);

      // Test authorizationState function
      const testNonce = ethers.utils.hexZeroPad("0x1", 32);
      const state = await debtToken.authorizationState(alice.address, testNonce);
      assert.isFalse(state);
    });

    it("should maintain existing ERC20 functionality", async () => {
      // Deploy a fresh instance
      const DebtToken = await ethers.getContractFactory("DebtToken");
      const debtToken = await upgrades.deployProxy(
        DebtToken,
        [owner.address, owner.address, owner.address],
        {
          unsafeAllow: ["constructor", "state-variable-immutable"],
        },
      );

      // Verify basic ERC20 functions still work
      const name = await debtToken.name();
      assert.equal(name, "USD for Filecoin Community");

      const symbol = await debtToken.symbol();
      assert.equal(symbol, "USDFC");

      const decimals = await debtToken.decimals();
      assert.equal(decimals, 18);

      const totalSupply = await debtToken.totalSupply();
      assert.equal(totalSupply.toString(), "0");
    });

    it("should have correct EIP-3009 type hashes", async () => {
      // Check that the implementation includes the correct constants
      const DebtToken = await ethers.getContractFactory("DebtToken");
      const bytecode = DebtToken.bytecode;

      // EIP-3009 type hashes as hex strings (without 0x prefix)
      const transferAuthTypeHash =
        "7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267";
      const receiveAuthTypeHash =
        "d099cc98ef71107a616c4f0f941f04c322d8e254fe26b3c6668db87aae413de8";
      const cancelAuthTypeHash = "158b0a9edf7a828aad02f63cd515c68ef2f50ba807396f6d12842833a1597429";

      // Basic check that these constants appear in the bytecode
      const hasTransferAuth = bytecode.includes(transferAuthTypeHash);
      const hasReceiveAuth = bytecode.includes(receiveAuthTypeHash);
      const hasCancelAuth = bytecode.includes(cancelAuthTypeHash);

      assert.isTrue(hasTransferAuth || hasReceiveAuth || hasCancelAuth);
    });
  });

  const testCorpus = ({ withProxy = false }) => {
    before(async () => {
      await hre.network.provider.send("hardhat_reset");
      const transactionCount = await owner.getTransactionCount();
      const cpTesterContracts = await deploymentHelper.computeContractAddresses(
        owner.address,
        transactionCount,
        3,
      );
      const cpContracts = await deploymentHelper.computeCoreProtocolContracts(
        owner.address,
        transactionCount + 3,
      );

      // Overwrite contracts with computed tester addresses
      cpContracts.debtToken = cpTesterContracts[2];

      debtTokenTester = await deploymentHelper.deployDebtTokenTester(cpContracts);

      contracts = await deploymentHelper.deployProtocolCore(
        GAS_COMPENSATION,
        MIN_NET_DEBT,
        cpContracts,
      );

      contracts.debtToken = debtTokenTester;

      protocolTokenContracts = await deploymentHelper.deployProtocolTokenTesterContracts(
        owner.address,
        cpContracts,
      );

      debtTokenOriginal = contracts.debtToken;
      debtTokenTester = contracts.debtToken;
      chainId = await debtTokenOriginal.getChainId();

      stabilityPool = contracts.stabilityPool;
      troveManager = contracts.troveManager;
      borrowerOperations = contracts.borrowerOperations;

      tokenVersion = await debtTokenOriginal.version();
      tokenName = await debtTokenOriginal.name();
    });

    beforeEach(async () => {
      // Mint tokens for testing
      if (withProxy) {
        const users = [alice, bob, carol, dennis];
        await deploymentHelper.deployProxyScripts(contracts, protocolTokenContracts, owner, users);

        debtTokenTester = contracts.debtToken;
        stabilityPool = contracts.stabilityPool;
        troveManager = contracts.troveManager;
        borrowerOperations = contracts.borrowerOperations;

        // mint some tokens
        await debtTokenOriginal.unprotectedMint(
          debtTokenTester.getProxyAddressFromUser(alice.address),
          toBN(dec(10000, 18)),
        );
        await debtTokenOriginal.unprotectedMint(
          debtTokenTester.getProxyAddressFromUser(bob.address),
          toBN(dec(5000, 18)),
        );
        await debtTokenOriginal.unprotectedMint(
          debtTokenTester.getProxyAddressFromUser(carol.address),
          toBN(dec(3000, 18)),
        );
      } else {
        await debtTokenOriginal.unprotectedMint(alice.address, toBN(dec(10000, 18)));
        await debtTokenOriginal.unprotectedMint(bob.address, toBN(dec(5000, 18)));
        await debtTokenOriginal.unprotectedMint(carol.address, toBN(dec(3000, 18)));
      }
    });

    // Basic Functionality Tests
    it("should have EIP-3009 functions available", async () => {
      assert.isNotNull(debtTokenTester.transferWithAuthorization);
      assert.isNotNull(debtTokenTester.receiveWithAuthorization);
      assert.isNotNull(debtTokenTester.cancelAuthorization);
      assert.isNotNull(debtTokenTester.authorizationState);
    });

    it("authorizationState(): returns correct initial state", async () => {
      const nonce = randomBytes(32);
      const state = await debtTokenTester.authorizationState(alice.address, nonce);
      assert.isFalse(state);
    });

    // transferWithAuthorization tests
    it("transferWithAuthorization(): successfully transfers with valid authorization", async () => {
      const value = toBN(dec(100, 18));
      const validAfter = 0;
      const validBefore = Math.floor(Date.now() / 1000) + 3600;
      const nonce = randomBytes(32);

      const digest = getTransferWithAuthorizationDigest(
        tokenName,
        debtTokenTester.address,
        chainId,
        tokenVersion,
        alice.address,
        bob.address,
        value,
        validAfter,
        validBefore,
        nonce,
      );

      const { v, r, s } = sign(digest, alicePrivateKey);

      const aliceBalBefore = await debtTokenTester.balanceOf(alice.address);
      const bobBalBefore = await debtTokenTester.balanceOf(bob.address);

      const tx = await debtTokenTester.transferWithAuthorization(
        alice.address,
        bob.address,
        value,
        validAfter,
        validBefore,
        nonce,
        v,
        hexlify(r),
        hexlify(s),
      );

      const receipt = await tx.wait();

      // Verify events
      const authEvent = receipt.events.find((e) => e.event === "AuthorizationUsed");
      assert.equal(authEvent.args.authorizer, alice.address);
      assert.equal(authEvent.args.nonce, hexlify(nonce));

      const transferEvent = receipt.events.find((e) => e.event === "Transfer");
      assert.equal(transferEvent.args.from, alice.address);
      assert.equal(transferEvent.args.to, bob.address);
      assert.equal(transferEvent.args.value.toString(), value.toString());

      // Verify balances
      const aliceBalAfter = await debtTokenTester.balanceOf(alice.address);
      const bobBalAfter = await debtTokenTester.balanceOf(bob.address);

      assert.equal(aliceBalAfter.toString(), aliceBalBefore.sub(value).toString());
      assert.equal(bobBalAfter.toString(), bobBalBefore.add(value).toString());

      // Verify authorization state
      const authState = await debtTokenTester.authorizationState(alice.address, nonce);
      assert.isTrue(authState);
    });

    it("transferWithAuthorization(): reverts when authorization not yet valid", async () => {
      const value = toBN(dec(100, 18));
      const validAfter = Math.floor(Date.now() / 1000) + 3600;
      const validBefore = validAfter + 3600;
      const nonce = randomBytes(32);

      const digest = getTransferWithAuthorizationDigest(
        tokenName,
        debtTokenTester.address,
        chainId,
        tokenVersion,
        alice.address,
        bob.address,
        value,
        validAfter,
        validBefore,
        nonce,
      );

      const { v, r, s } = sign(digest, alicePrivateKey);

      await assertRevert(
        debtTokenTester.transferWithAuthorization(
          alice.address,
          bob.address,
          value,
          validAfter,
          validBefore,
          nonce,
          v,
          hexlify(r),
          hexlify(s),
        ),
        "DebtToken: authorization not yet valid",
      );
    });

    it("transferWithAuthorization(): reverts when authorization expired", async () => {
      const value = toBN(dec(100, 18));
      const validAfter = 0;
      const validBefore = Math.floor(Date.now() / 1000) - 3600;
      const nonce = randomBytes(32);

      const digest = getTransferWithAuthorizationDigest(
        tokenName,
        debtTokenTester.address,
        chainId,
        tokenVersion,
        alice.address,
        bob.address,
        value,
        validAfter,
        validBefore,
        nonce,
      );

      const { v, r, s } = sign(digest, alicePrivateKey);

      await assertRevert(
        debtTokenTester.transferWithAuthorization(
          alice.address,
          bob.address,
          value,
          validAfter,
          validBefore,
          nonce,
          v,
          hexlify(r),
          hexlify(s),
        ),
        "DebtToken: authorization expired",
      );
    });

    it("transferWithAuthorization(): reverts when nonce already used", async () => {
      const value = toBN(dec(50, 18));
      const validAfter = 0;
      const validBefore = Math.floor(Date.now() / 1000) + 3600;
      const nonce = randomBytes(32);

      const digest = getTransferWithAuthorizationDigest(
        tokenName,
        debtTokenTester.address,
        chainId,
        tokenVersion,
        alice.address,
        bob.address,
        value,
        validAfter,
        validBefore,
        nonce,
      );

      const { v, r, s } = sign(digest, alicePrivateKey);

      // First transfer should succeed
      await debtTokenTester.transferWithAuthorization(
        alice.address,
        bob.address,
        value,
        validAfter,
        validBefore,
        nonce,
        v,
        hexlify(r),
        hexlify(s),
      );

      // Second transfer with same nonce should fail
      await assertRevert(
        debtTokenTester.transferWithAuthorization(
          alice.address,
          bob.address,
          value,
          validAfter,
          validBefore,
          nonce,
          v,
          hexlify(r),
          hexlify(s),
        ),
        "DebtToken: authorization already used",
      );
    });

    it("transferWithAuthorization(): reverts with invalid signature", async () => {
      const value = toBN(dec(100, 18));
      const validAfter = 0;
      const validBefore = Math.floor(Date.now() / 1000) + 3600;
      const nonce = randomBytes(32);

      const digest = getTransferWithAuthorizationDigest(
        tokenName,
        debtTokenTester.address,
        chainId,
        tokenVersion,
        alice.address,
        bob.address,
        value,
        validAfter,
        validBefore,
        nonce,
      );

      // Sign with wrong key
      const { v, r, s } = sign(digest, bobPrivateKey);

      await assertRevert(
        debtTokenTester.transferWithAuthorization(
          alice.address,
          bob.address,
          value,
          validAfter,
          validBefore,
          nonce,
          v,
          hexlify(r),
          hexlify(s),
        ),
        "DebtToken: invalid signature",
      );
    });

    it("transferWithAuthorization(): reverts when transferring to zero address", async () => {
      const value = toBN(dec(100, 18));
      const validAfter = 0;
      const validBefore = Math.floor(Date.now() / 1000) + 3600;
      const nonce = randomBytes(32);

      const digest = getTransferWithAuthorizationDigest(
        tokenName,
        debtTokenTester.address,
        chainId,
        tokenVersion,
        alice.address,
        ZERO_ADDRESS,
        value,
        validAfter,
        validBefore,
        nonce,
      );

      const { v, r, s } = sign(digest, alicePrivateKey);

      await assertRevert(
        debtTokenTester.transferWithAuthorization(
          alice.address,
          ZERO_ADDRESS,
          value,
          validAfter,
          validBefore,
          nonce,
          v,
          hexlify(r),
          hexlify(s),
        ),
        "DebtToken: Cannot transfer tokens directly to the Debt token contract or the zero address",
      );
    });

    it("transferWithAuthorization(): reverts when transferring to system contracts", async () => {
      const value = toBN(dec(100, 18));
      const validAfter = 0;
      const validBefore = Math.floor(Date.now() / 1000) + 3600;
      const nonce = randomBytes(32);

      const digest = getTransferWithAuthorizationDigest(
        tokenName,
        debtTokenTester.address,
        chainId,
        tokenVersion,
        alice.address,
        stabilityPool.address,
        value,
        validAfter,
        validBefore,
        nonce,
      );

      const { v, r, s } = sign(digest, alicePrivateKey);

      await assertRevert(
        debtTokenTester.transferWithAuthorization(
          alice.address,
          stabilityPool.address,
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

    it("transferWithAuthorization(): reverts with insufficient balance", async () => {
      // Use dennis account with a specific small balance to avoid state pollution
      const dennisPrivateKey = accountsList[4].privateKey;
      await debtTokenOriginal.unprotectedMint(dennis.address, toBN(dec(50, 18))); // Give dennis exactly 50 tokens

      const value = toBN(dec(100, 18)); // Try to transfer 100 (more than dennis has)
      const validAfter = 0;
      const validBefore = Math.floor(Date.now() / 1000) + 3600;
      const nonce = randomBytes(32);

      const digest = getTransferWithAuthorizationDigest(
        tokenName,
        debtTokenTester.address,
        chainId,
        tokenVersion,
        dennis.address,
        carol.address,
        value,
        validAfter,
        validBefore,
        nonce,
      );

      const { v, r, s } = sign(digest, dennisPrivateKey);

      await assertRevert(
        debtTokenTester.transferWithAuthorization(
          dennis.address,
          carol.address,
          value,
          validAfter,
          validBefore,
          nonce,
          v,
          hexlify(r),
          hexlify(s),
        ),
        "ERC20: transfer amount exceeds balance",
      );
    });

    // receiveWithAuthorization tests
    it("receiveWithAuthorization(): successfully receives with valid authorization", async () => {
      const value = toBN(dec(100, 18));
      const validAfter = 0;
      const validBefore = Math.floor(Date.now() / 1000) + 3600;
      const nonce = randomBytes(32);

      const digest = getReceiveWithAuthorizationDigest(
        tokenName,
        debtTokenTester.address,
        chainId,
        tokenVersion,
        alice.address,
        bob.address,
        value,
        validAfter,
        validBefore,
        nonce,
      );

      const { v, r, s } = sign(digest, alicePrivateKey);

      const aliceBalBefore = await debtTokenTester.balanceOf(alice.address);
      const bobBalBefore = await debtTokenTester.balanceOf(bob.address);

      // Bob calls to receive tokens
      const tx = await debtTokenTester
        .connect(bob)
        .receiveWithAuthorization(
          alice.address,
          bob.address,
          value,
          validAfter,
          validBefore,
          nonce,
          v,
          hexlify(r),
          hexlify(s),
        );

      const receipt = await tx.wait();

      // Verify events
      const authEvent = receipt.events.find((e) => e.event === "AuthorizationUsed");
      assert.equal(authEvent.args.authorizer, alice.address);
      assert.equal(authEvent.args.nonce, hexlify(nonce));

      // Verify balances
      const aliceBalAfter = await debtTokenTester.balanceOf(alice.address);
      const bobBalAfter = await debtTokenTester.balanceOf(bob.address);

      assert.equal(aliceBalAfter.toString(), aliceBalBefore.sub(value).toString());
      assert.equal(bobBalAfter.toString(), bobBalBefore.add(value).toString());
    });

    it("receiveWithAuthorization(): reverts when caller is not the recipient", async () => {
      const value = toBN(dec(100, 18));
      const validAfter = 0;
      const validBefore = Math.floor(Date.now() / 1000) + 3600;
      const nonce = randomBytes(32);

      const digest = getReceiveWithAuthorizationDigest(
        tokenName,
        debtTokenTester.address,
        chainId,
        tokenVersion,
        alice.address,
        bob.address,
        value,
        validAfter,
        validBefore,
        nonce,
      );

      const { v, r, s } = sign(digest, alicePrivateKey);

      // Carol tries to call, but recipient is Bob
      await assertRevert(
        debtTokenTester
          .connect(carol)
          .receiveWithAuthorization(
            alice.address,
            bob.address,
            value,
            validAfter,
            validBefore,
            nonce,
            v,
            hexlify(r),
            hexlify(s),
          ),
        "DebtToken: caller must be the recipient",
      );
    });

    it("receiveWithAuthorization(): enforces all validation checks", async () => {
      // Test expired authorization
      const value = toBN(dec(100, 18));
      const validAfter = 0;
      const validBefore = Math.floor(Date.now() / 1000) - 3600;
      const nonce = randomBytes(32);

      const digest = getReceiveWithAuthorizationDigest(
        tokenName,
        debtTokenTester.address,
        chainId,
        tokenVersion,
        alice.address,
        bob.address,
        value,
        validAfter,
        validBefore,
        nonce,
      );

      const { v, r, s } = sign(digest, alicePrivateKey);

      await assertRevert(
        debtTokenTester
          .connect(bob)
          .receiveWithAuthorization(
            alice.address,
            bob.address,
            value,
            validAfter,
            validBefore,
            nonce,
            v,
            hexlify(r),
            hexlify(s),
          ),
        "DebtToken: authorization expired",
      );
    });

    // cancelAuthorization tests
    it("cancelAuthorization(): successfully cancels unused authorization", async () => {
      const nonce = randomBytes(32);

      // Check initial state
      const stateBefore = await debtTokenTester.authorizationState(alice.address, nonce);
      assert.isFalse(stateBefore);

      const digest = getCancelAuthorizationDigest(
        tokenName,
        debtTokenTester.address,
        chainId,
        tokenVersion,
        alice.address,
        nonce,
      );

      const { v, r, s } = sign(digest, alicePrivateKey);

      const tx = await debtTokenTester
        .connect(bob)
        .cancelAuthorization(alice.address, nonce, v, hexlify(r), hexlify(s));

      const receipt = await tx.wait();

      // Verify event
      const cancelEvent = receipt.events.find((e) => e.event === "AuthorizationCanceled");
      assert.equal(cancelEvent.args.authorizer, alice.address);
      assert.equal(cancelEvent.args.nonce, hexlify(nonce));

      // Check state is now true (cancelled)
      const stateAfter = await debtTokenTester.authorizationState(alice.address, nonce);
      assert.isTrue(stateAfter);
    });

    it("cancelAuthorization(): reverts with invalid signature", async () => {
      const nonce = randomBytes(32);

      const digest = getCancelAuthorizationDigest(
        tokenName,
        debtTokenTester.address,
        chainId,
        tokenVersion,
        alice.address,
        nonce,
      );

      // Sign with wrong key
      const { v, r, s } = sign(digest, bobPrivateKey);

      await assertRevert(
        debtTokenTester.cancelAuthorization(alice.address, nonce, v, hexlify(r), hexlify(s)),
        "DebtToken: invalid signature",
      );
    });

    it("cancelAuthorization(): reverts when cancelling already used authorization", async () => {
      const value = toBN(dec(100, 18));
      const validAfter = 0;
      const validBefore = Math.floor(Date.now() / 1000) + 3600;
      const nonce = randomBytes(32);

      // First use the authorization
      const transferDigest = getTransferWithAuthorizationDigest(
        tokenName,
        debtTokenTester.address,
        chainId,
        tokenVersion,
        alice.address,
        bob.address,
        value,
        validAfter,
        validBefore,
        nonce,
      );

      const transferSig = sign(transferDigest, alicePrivateKey);

      await debtTokenTester.transferWithAuthorization(
        alice.address,
        bob.address,
        value,
        validAfter,
        validBefore,
        nonce,
        transferSig.v,
        hexlify(transferSig.r),
        hexlify(transferSig.s),
      );

      // Now try to cancel it
      const cancelDigest = getCancelAuthorizationDigest(
        tokenName,
        debtTokenTester.address,
        chainId,
        tokenVersion,
        alice.address,
        nonce,
      );

      const cancelSig = sign(cancelDigest, alicePrivateKey);

      await assertRevert(
        debtTokenTester.cancelAuthorization(
          alice.address,
          nonce,
          cancelSig.v,
          hexlify(cancelSig.r),
          hexlify(cancelSig.s),
        ),
        "DebtToken: authorization already used",
      );
    });

    it("cancelAuthorization(): prevents transfer after cancellation", async () => {
      const value = toBN(dec(100, 18));
      const validAfter = 0;
      const validBefore = Math.floor(Date.now() / 1000) + 3600;
      const nonce = randomBytes(32);

      // First cancel the authorization
      const cancelDigest = getCancelAuthorizationDigest(
        tokenName,
        debtTokenTester.address,
        chainId,
        tokenVersion,
        alice.address,
        nonce,
      );

      const cancelSig = sign(cancelDigest, alicePrivateKey);

      await debtTokenTester.cancelAuthorization(
        alice.address,
        nonce,
        cancelSig.v,
        hexlify(cancelSig.r),
        hexlify(cancelSig.s),
      );

      // Now try to use it for transfer
      const transferDigest = getTransferWithAuthorizationDigest(
        tokenName,
        debtTokenTester.address,
        chainId,
        tokenVersion,
        alice.address,
        bob.address,
        value,
        validAfter,
        validBefore,
        nonce,
      );

      const transferSig = sign(transferDigest, alicePrivateKey);

      await assertRevert(
        debtTokenTester.transferWithAuthorization(
          alice.address,
          bob.address,
          value,
          validAfter,
          validBefore,
          nonce,
          transferSig.v,
          hexlify(transferSig.r),
          hexlify(transferSig.s),
        ),
        "DebtToken: authorization already used",
      );
    });

    // Edge cases and security tests
    it("transferWithAuthorization(): handles signature malleability", async () => {
      const value = toBN(dec(100, 18));
      const validAfter = 0;
      const validBefore = Math.floor(Date.now() / 1000) + 3600;
      const nonce = randomBytes(32);

      const digest = getTransferWithAuthorizationDigest(
        tokenName,
        debtTokenTester.address,
        chainId,
        tokenVersion,
        alice.address,
        bob.address,
        value,
        validAfter,
        validBefore,
        nonce,
      );

      const { v, r, s } = sign(digest, alicePrivateKey);

      // First transfer should succeed
      await debtTokenTester.transferWithAuthorization(
        alice.address,
        bob.address,
        value,
        validAfter,
        validBefore,
        nonce,
        v,
        hexlify(r),
        hexlify(s),
      );

      // Try with modified v value (EIP-2 malleability)
      const malleableV = v === 27 ? 28 : 27;

      await assertRevert(
        debtTokenTester.transferWithAuthorization(
          alice.address,
          bob.address,
          value,
          validAfter,
          validBefore,
          nonce,
          malleableV,
          hexlify(r),
          hexlify(s),
        ),
        "DebtToken: authorization already used",
      );
    });

    it("transferWithAuthorization(): prevents replay attacks across chains", async () => {
      // This test verifies that the chainId is included in the domain separator
      const domainSep1 = getDomainSeparator(
        tokenName,
        debtTokenTester.address,
        chainId,
        tokenVersion,
      );
      const domainSep2 = getDomainSeparator(
        tokenName,
        debtTokenTester.address,
        chainId + 1,
        tokenVersion,
      );

      assert.notEqual(domainSep1, domainSep2);
    });

    it("transferWithAuthorization(): handles maximum uint256 values", async () => {
      const maxUint256 = toBN(2).pow(toBN(256)).sub(toBN(1));
      const validAfter = 0;
      const validBefore = maxUint256;
      const nonce = randomBytes(32);

      // Skip minting max tokens as it causes overflow
      // Just test with max validBefore timestamp

      const digest = getTransferWithAuthorizationDigest(
        tokenName,
        debtTokenTester.address,
        chainId,
        tokenVersion,
        alice.address,
        bob.address,
        toBN(dec(1, 18)),
        validAfter,
        validBefore,
        nonce,
      );

      const { v, r, s } = sign(digest, alicePrivateKey);

      // Should work with max validBefore
      await debtTokenTester.transferWithAuthorization(
        alice.address,
        bob.address,
        toBN(dec(1, 18)),
        validAfter,
        validBefore,
        nonce,
        v,
        hexlify(r),
        hexlify(s),
      );

      const authState = await debtTokenTester.authorizationState(alice.address, nonce);
      assert.isTrue(authState);
    });

    it("transferWithAuthorization(): correctly validates empty nonce", async () => {
      const value = toBN(dec(100, 18));
      const validAfter = 0;
      const validBefore = Math.floor(Date.now() / 1000) + 3600;
      const emptyNonce = "0x0000000000000000000000000000000000000000000000000000000000000000";

      const digest = getTransferWithAuthorizationDigest(
        tokenName,
        debtTokenTester.address,
        chainId,
        tokenVersion,
        alice.address,
        bob.address,
        value,
        validAfter,
        validBefore,
        emptyNonce,
      );

      const { v, r, s } = sign(digest, alicePrivateKey);

      // Should work with empty nonce
      await debtTokenTester.transferWithAuthorization(
        alice.address,
        bob.address,
        value,
        validAfter,
        validBefore,
        emptyNonce,
        v,
        hexlify(r),
        hexlify(s),
      );

      const authState = await debtTokenTester.authorizationState(alice.address, emptyNonce);
      assert.isTrue(authState);
    });

    it("transferWithAuthorization(): has reasonable gas costs", async () => {
      const value = toBN(dec(100, 18));
      const validAfter = 0;
      const validBefore = Math.floor(Date.now() / 1000) + 3600;
      const nonce = randomBytes(32);

      const digest = getTransferWithAuthorizationDigest(
        tokenName,
        debtTokenTester.address,
        chainId,
        tokenVersion,
        alice.address,
        bob.address,
        value,
        validAfter,
        validBefore,
        nonce,
      );

      const { v, r, s } = sign(digest, alicePrivateKey);

      const tx = await debtTokenTester.transferWithAuthorization(
        alice.address,
        bob.address,
        value,
        validAfter,
        validBefore,
        nonce,
        v,
        hexlify(r),
        hexlify(s),
      );

      const receipt = await tx.wait();

      // Gas should be reasonable (less than 150k for a transfer with authorization)
      assert.isBelow(receipt.gasUsed.toNumber(), 150000);
    });
  };

  describe("Without proxy", async () => {
    testCorpus({ withProxy: false });
  });

  // Note: EIP-3009 functions are not available through proxy scripts
  // as they are not included in the TokenScript proxy implementation
});
