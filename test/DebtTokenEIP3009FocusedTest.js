const { ethers, upgrades } = require("hardhat");
const { expect } = require("chai");
const { keccak256 } = require("@ethersproject/keccak256");
const { defaultAbiCoder } = require("@ethersproject/abi");
const { toUtf8Bytes } = require("@ethersproject/strings");
const { pack } = require("@ethersproject/solidity");
const { hexlify } = require("@ethersproject/bytes");
const { ecsign } = require("ethereumjs-util");
const { randomBytes } = require("@ethersproject/random");
const testHelpers = require("../utils/testHelpers.js");
const { assertRevert } = testHelpers.TestHelper;

describe("DebtToken EIP-3009 Focused Tests", function () {
  let DebtToken;
  let debtToken;
  let owner, alice, bob, carol;
  let chainId;
  let tokenName, tokenVersion;

  // Helper to create deterministic private keys
  const createPrivateKey = (seed) => {
    return ethers.utils.keccak256(ethers.utils.toUtf8Bytes(seed));
  };

  const alicePrivateKey = createPrivateKey("alice");
  const bobPrivateKey = createPrivateKey("bob");

  // Sign helper
  const sign = (digest, privateKey) => {
    return ecsign(Buffer.from(digest.slice(2), "hex"), Buffer.from(privateKey.slice(2), "hex"));
  };

  // EIP-3009 type hashes
  const TRANSFER_WITH_AUTHORIZATION_TYPEHASH = keccak256(
    toUtf8Bytes(
      "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)",
    ),
  );

  // Domain separator helper
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

  // Get transfer authorization digest
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
              [
                TRANSFER_WITH_AUTHORIZATION_TYPEHASH,
                from,
                to,
                value,
                validAfter,
                validBefore,
                nonce,
              ],
            ),
          ),
        ],
      ),
    );
  };

  beforeEach(async function () {
    [owner, carol] = await ethers.getSigners();

    // Create alice and bob wallets from the deterministic private keys
    alice = new ethers.Wallet(alicePrivateKey, ethers.provider);
    bob = new ethers.Wallet(bobPrivateKey, ethers.provider);

    // Fund alice and bob
    await owner.sendTransaction({ to: alice.address, value: ethers.utils.parseEther("10") });
    await owner.sendTransaction({ to: bob.address, value: ethers.utils.parseEther("10") });

    // Deploy DebtToken with proxy using upgrades plugin
    DebtToken = await ethers.getContractFactory("DebtToken");

    debtToken = await upgrades.deployProxy(
      DebtToken,
      [
        owner.address, // mock troveManager
        owner.address, // mock stabilityPool
        owner.address, // mock borrowerOperations
      ],
      {
        unsafeAllow: ["constructor", "state-variable-immutable"],
      },
    );

    await debtToken.deployed();

    // Get token info
    tokenName = await debtToken.name();
    tokenVersion = await debtToken.version();
    chainId = (await ethers.provider.getNetwork()).chainId;

    // Mint some tokens to alice (as mock borrowerOperations)
    await debtToken.connect(owner).mint(alice.address, ethers.utils.parseUnits("10000", 18));
  });

  describe("EIP-3009 Core Functionality", function () {
    it("should have EIP-3009 functions available", async function () {
      // Verify functions exist
      expect(typeof debtToken.transferWithAuthorization).to.equal("function");
      expect(typeof debtToken.receiveWithAuthorization).to.equal("function");
      expect(typeof debtToken.cancelAuthorization).to.equal("function");
      expect(typeof debtToken.authorizationState).to.equal("function");
    });

    it("should execute transferWithAuthorization successfully", async function () {
      const from = alice.address;
      const to = bob.address;
      const value = ethers.utils.parseUnits("100", 18);
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

      const aliceBalBefore = await debtToken.balanceOf(alice.address);
      const bobBalBefore = await debtToken.balanceOf(bob.address);

      // Execute transfer
      const tx = await debtToken.transferWithAuthorization(
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

      const receipt = await tx.wait();

      // Check balances
      const aliceBalAfter = await debtToken.balanceOf(alice.address);
      const bobBalAfter = await debtToken.balanceOf(bob.address);

      expect(aliceBalAfter.toString()).to.equal(aliceBalBefore.sub(value).toString());
      expect(bobBalAfter.toString()).to.equal(bobBalBefore.add(value).toString());

      // Check event
      const authEvent = receipt.events.find((e) => e.event === "AuthorizationUsed");
      expect(authEvent).to.not.be.undefined;
      expect(authEvent.args.authorizer).to.equal(from);

      // Check authorization state
      const authState = await debtToken.authorizationState(from, nonce);
      expect(authState).to.be.true;
    });

    it("should revert on invalid time bounds", async function () {
      const from = alice.address;
      const to = bob.address;
      const value = ethers.utils.parseUnits("100", 18);
      const validAfter = Math.floor(Date.now() / 1000) + 3600; // 1 hour in future
      const validBefore = validAfter + 3600;
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
        "DebtToken: authorization not yet valid",
      );
    });

    it("should revert on reused nonce", async function () {
      const from = alice.address;
      const to = bob.address;
      const value = ethers.utils.parseUnits("50", 18);
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

      // First transfer should succeed
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

      // Second transfer with same nonce should fail
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
        "DebtToken: authorization already used",
      );
    });

    it("should maintain transfer restrictions", async function () {
      const from = alice.address;
      const to = debtToken.address; // Invalid recipient (self)
      const value = ethers.utils.parseUnits("100", 18);
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
        "DebtToken: Cannot transfer tokens directly to the Debt token contract or the zero address",
      );
    });

    it("should track authorization state correctly", async function () {
      const nonce1 = randomBytes(32);
      const nonce2 = randomBytes(32);

      // Initially both should be false
      expect(await debtToken.authorizationState(alice.address, nonce1)).to.be.false;
      expect(await debtToken.authorizationState(alice.address, nonce2)).to.be.false;

      // Use nonce1
      const digest = getTransferWithAuthorizationDigest(
        tokenName,
        debtToken.address,
        chainId,
        tokenVersion,
        alice.address,
        bob.address,
        ethers.utils.parseUnits("10", 18),
        0,
        Math.floor(Date.now() / 1000) + 3600,
        nonce1,
      );

      const { v, r, s } = sign(digest, alicePrivateKey);

      await debtToken.transferWithAuthorization(
        alice.address,
        bob.address,
        ethers.utils.parseUnits("10", 18),
        0,
        Math.floor(Date.now() / 1000) + 3600,
        nonce1,
        v,
        hexlify(r),
        hexlify(s),
      );

      // Now nonce1 should be true, nonce2 still false
      expect(await debtToken.authorizationState(alice.address, nonce1)).to.be.true;
      expect(await debtToken.authorizationState(alice.address, nonce2)).to.be.false;
    });
  });

  describe("Gas measurements", function () {
    it("should have reasonable gas costs for transferWithAuthorization", async function () {
      const from = alice.address;
      const to = bob.address;
      const value = ethers.utils.parseUnits("100", 18);
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

      const tx = await debtToken.transferWithAuthorization(
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

      const receipt = await tx.wait();
      console.log(`      Gas used: ${receipt.gasUsed.toString()}`);

      // Should be less than 110k gas (allowing some margin)
      expect(receipt.gasUsed.toNumber()).to.be.lessThan(110000);
    });
  });
});
