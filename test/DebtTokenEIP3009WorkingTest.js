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

describe("DebtToken EIP-3009 Functionality Tests", function () {
  let debtToken;
  let owner, alice, bob, carol;
  let chainId;
  let tokenName, tokenVersion;

  // Helper to create private keys
  const createPrivateKey = () => {
    const wallet = ethers.Wallet.createRandom();
    return wallet.privateKey;
  };

  const alicePrivateKey = createPrivateKey();
  const bobPrivateKey = createPrivateKey();

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

  const RECEIVE_WITH_AUTHORIZATION_TYPEHASH = keccak256(
    toUtf8Bytes(
      "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)",
    ),
  );

  const CANCEL_AUTHORIZATION_TYPEHASH = keccak256(
    toUtf8Bytes("CancelAuthorization(address authorizer,bytes32 nonce)"),
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

  // Get receive authorization digest
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
              [
                RECEIVE_WITH_AUTHORIZATION_TYPEHASH,
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

  // Get cancel authorization digest
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

  before(async function () {
    [owner, carol] = await ethers.getSigners();

    // Create alice and bob from the private keys
    alice = new ethers.Wallet(alicePrivateKey, ethers.provider);
    bob = new ethers.Wallet(bobPrivateKey, ethers.provider);

    // Fund alice and bob
    await owner.sendTransaction({ to: alice.address, value: ethers.utils.parseEther("10") });
    await owner.sendTransaction({ to: bob.address, value: ethers.utils.parseEther("10") });

    // Deploy DebtToken with minimal setup
    const DebtToken = await ethers.getContractFactory("DebtToken");
    debtToken = await upgrades.deployProxy(
      DebtToken,
      [
        owner.address, // troveManager (using owner as mock)
        owner.address, // stabilityPool (using owner as mock)
        owner.address, // borrowerOperations (using owner as mock)
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

  describe("transferWithAuthorization", function () {
    it("should transfer tokens with valid authorization", async function () {
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

      // Check events
      const authEvent = receipt.events.find((e) => e.event === "AuthorizationUsed");
      expect(authEvent).to.not.be.undefined;
      expect(authEvent.args.authorizer).to.equal(from);
      expect(authEvent.args.nonce).to.equal(hexlify(nonce));

      const transferEvent = receipt.events.find((e) => e.event === "Transfer");
      expect(transferEvent).to.not.be.undefined;
      expect(transferEvent.args.from).to.equal(from);
      expect(transferEvent.args.to).to.equal(to);
      expect(transferEvent.args.value.toString()).to.equal(value.toString());

      const aliceBalAfter = await debtToken.balanceOf(alice.address);
      const bobBalAfter = await debtToken.balanceOf(bob.address);

      expect(aliceBalAfter.toString()).to.equal(aliceBalBefore.sub(value).toString());
      expect(bobBalAfter.toString()).to.equal(bobBalBefore.add(value).toString());

      // Check authorization state
      const authState = await debtToken.authorizationState(from, nonce);
      expect(authState).to.be.true;
    });

    it("should revert when authorization not yet valid", async function () {
      const from = alice.address;
      const to = bob.address;
      const value = ethers.utils.parseUnits("100", 18);
      const validAfter = Math.floor(Date.now() / 1000) + 3600;
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

    it("should revert when authorization expired", async function () {
      const from = alice.address;
      const to = bob.address;
      const value = ethers.utils.parseUnits("100", 18);
      const validAfter = 0;
      const validBefore = Math.floor(Date.now() / 1000) - 3600;
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
        "DebtToken: authorization expired",
      );
    });

    it("should revert when authorization already used", async function () {
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

    it("should revert with invalid signature", async function () {
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

      // Sign with wrong key
      const { v, r, s } = sign(digest, bobPrivateKey);

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
        "DebtToken: invalid signature",
      );
    });
  });

  describe("receiveWithAuthorization", function () {
    it("should transfer tokens when called by recipient", async function () {
      const from = alice.address;
      const to = bob.address;
      const value = ethers.utils.parseUnits("100", 18);
      const validAfter = 0;
      const validBefore = Math.floor(Date.now() / 1000) + 3600;
      const nonce = randomBytes(32);

      const digest = getReceiveWithAuthorizationDigest(
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

      // Bob calls the function
      const tx = await debtToken
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

      const receipt = await tx.wait();
      const authEvent = receipt.events.find((e) => e.event === "AuthorizationUsed");
      expect(authEvent).to.not.be.undefined;
      expect(authEvent.args.authorizer).to.equal(from);
      expect(authEvent.args.nonce).to.equal(hexlify(nonce));

      const aliceBalAfter = await debtToken.balanceOf(alice.address);
      const bobBalAfter = await debtToken.balanceOf(bob.address);

      expect(aliceBalAfter.toString()).to.equal(aliceBalBefore.sub(value).toString());
      expect(bobBalAfter.toString()).to.equal(bobBalBefore.add(value).toString());
    });

    it("should revert when not called by recipient", async function () {
      const from = alice.address;
      const to = bob.address;
      const value = ethers.utils.parseUnits("100", 18);
      const validAfter = 0;
      const validBefore = Math.floor(Date.now() / 1000) + 3600;
      const nonce = randomBytes(32);

      const digest = getReceiveWithAuthorizationDigest(
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

      // Carol tries to call the function
      await assertRevert(
        debtToken
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
          ),
        "DebtToken: caller must be the recipient",
      );
    });
  });

  describe("cancelAuthorization", function () {
    it("should cancel unused authorization", async function () {
      const authorizer = alice.address;
      const nonce = randomBytes(32);

      const digest = getCancelAuthorizationDigest(
        tokenName,
        debtToken.address,
        chainId,
        tokenVersion,
        authorizer,
        nonce,
      );

      const { v, r, s } = sign(digest, alicePrivateKey);

      // Check authorization state before
      const authStateBefore = await debtToken.authorizationState(authorizer, nonce);
      expect(authStateBefore).to.be.false;

      const tx = await debtToken.cancelAuthorization(authorizer, nonce, v, hexlify(r), hexlify(s));

      const receipt = await tx.wait();
      const cancelEvent = receipt.events.find((e) => e.event === "AuthorizationCanceled");
      expect(cancelEvent).to.not.be.undefined;
      expect(cancelEvent.args.authorizer).to.equal(authorizer);
      expect(cancelEvent.args.nonce).to.equal(hexlify(nonce));

      // Check authorization state after
      const authStateAfter = await debtToken.authorizationState(authorizer, nonce);
      expect(authStateAfter).to.be.true;
    });

    it("should revert when canceling already used authorization", async function () {
      const from = alice.address;
      const to = bob.address;
      const value = ethers.utils.parseUnits("100", 18);
      const validAfter = 0;
      const validBefore = Math.floor(Date.now() / 1000) + 3600;
      const nonce = randomBytes(32);

      // First use the authorization
      const transferDigest = getTransferWithAuthorizationDigest(
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

      const transferSig = sign(transferDigest, alicePrivateKey);

      await debtToken.transferWithAuthorization(
        from,
        to,
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
        debtToken.address,
        chainId,
        tokenVersion,
        from,
        nonce,
      );

      const cancelSig = sign(cancelDigest, alicePrivateKey);

      await assertRevert(
        debtToken.cancelAuthorization(
          from,
          nonce,
          cancelSig.v,
          hexlify(cancelSig.r),
          hexlify(cancelSig.s),
        ),
        "DebtToken: authorization already used",
      );
    });
  });

  describe("authorizationState", function () {
    it("should return false for unused nonce", async function () {
      const nonce = randomBytes(32);
      const state = await debtToken.authorizationState(alice.address, nonce);
      expect(state).to.be.false;
    });

    it("should return true for used nonce", async function () {
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

      const state = await debtToken.authorizationState(from, nonce);
      expect(state).to.be.true;
    });
  });

  describe("Gas measurements", function () {
    it("should have reasonable gas costs", async function () {
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
      console.log(`      Gas used for transferWithAuthorization: ${receipt.gasUsed.toString()}`);

      // Gas should be reasonable (less than 100k)
      expect(receipt.gasUsed.toNumber()).to.be.lessThan(100000);
    });
  });
});
