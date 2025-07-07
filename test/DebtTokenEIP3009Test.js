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

contract("DebtToken - EIP3009 Functionality", async () => {
  let signers;
  let owner, alice, bob, carol, dennis, erin;

  const ownerPrivateKey = accountsList[0].privateKey;
  const alicePrivateKey = accountsList[1].privateKey;
  const bobPrivateKey = accountsList[2].privateKey;

  let chainId;
  let debtToken;
  let stabilityPool;
  let troveManager;
  let borrowerOperations;
  let activePool;
  let priceFeed;

  let contracts;

  let tokenName;
  let tokenVersion;

  const openTrove = async (signer, params = {}) => {
    return contracts.borrowerOperations
      .connect(signer)
      .openTrove(
        params.maxFeePercentage || toBN(dec(5, 16)),
        params.debtAmount || MIN_NET_DEBT,
        ZERO_ADDRESS,
        ZERO_ADDRESS,
        { value: params.collAmount || dec(100, "ether") },
      );
  };

  before(async () => {
    signers = await ethers.getSigners();
    [owner, alice, bob, carol, dennis, erin] = await signers.splice(0, 6);

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

    // Set price to $100
    await priceFeed.setPrice(dec(100, 18));

    tokenName = await debtToken.name();
    tokenVersion = await debtToken.version();
    chainId = (await ethers.provider.getNetwork()).chainId;

    // Setup: Alice opens trove and gets some debt tokens
    await openTrove(alice, { collAmount: dec(100, "ether"), debtAmount: dec(10000, 18) });
  });

  describe("transferWithAuthorization", () => {
    it("should transfer tokens with valid authorization", async () => {
      const from = alice.address;
      const to = bob.address;
      const value = toBN(dec(100, 18));
      const validAfter = 0;
      const validBefore = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
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

      const aliceBalAfter = await debtToken.balanceOf(alice.address);
      const bobBalAfter = await debtToken.balanceOf(bob.address);

      assert.isTrue(aliceBalAfter.eq(aliceBalBefore.sub(value)));
      assert.isTrue(bobBalAfter.eq(bobBalBefore.add(value)));

      // Check event
      const receipt = await tx.wait();
      const event = receipt.events.find((e) => e.event === "AuthorizationUsed");
      assert.equal(event.args.authorizer, from);
      assert.equal(event.args.nonce, nonce);

      // Check authorization state
      const authState = await debtToken.authorizationState(from, nonce);
      assert.isTrue(authState);
    });

    it("should revert when authorization not yet valid", async () => {
      const from = alice.address;
      const to = bob.address;
      const value = toBN(dec(100, 18));
      const validAfter = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
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

    it("should revert when authorization expired", async () => {
      const from = alice.address;
      const to = bob.address;
      const value = toBN(dec(100, 18));
      const validAfter = 0;
      const validBefore = Math.floor(Date.now() / 1000) - 3600; // 1 hour ago
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

    it("should revert when authorization already used", async () => {
      const from = alice.address;
      const to = bob.address;
      const value = toBN(dec(100, 18));
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

    it("should revert with invalid signature", async () => {
      const from = alice.address;
      const to = bob.address;
      const value = toBN(dec(100, 18));
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

    it("should revert when transferring to protocol contracts", async () => {
      const from = alice.address;
      const to = stabilityPool.address;
      const value = toBN(dec(100, 18));
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

  describe("receiveWithAuthorization", () => {
    it("should transfer tokens when called by recipient", async () => {
      const from = alice.address;
      const to = bob.address;
      const value = toBN(dec(100, 18));
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

      const aliceBalAfter = await debtToken.balanceOf(alice.address);
      const bobBalAfter = await debtToken.balanceOf(bob.address);

      assert.isTrue(aliceBalAfter.eq(aliceBalBefore.sub(value)));
      assert.isTrue(bobBalAfter.eq(bobBalBefore.add(value)));

      // Check event
      const receipt = await tx.wait();
      const event = receipt.events.find((e) => e.event === "AuthorizationUsed");
      assert.equal(event.args.authorizer, from);
      assert.equal(event.args.nonce, nonce);
    });

    it("should revert when not called by recipient", async () => {
      const from = alice.address;
      const to = bob.address;
      const value = toBN(dec(100, 18));
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

  describe("cancelAuthorization", () => {
    it("should cancel unused authorization", async () => {
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
      assert.isFalse(authStateBefore);

      const tx = await debtToken.cancelAuthorization(authorizer, nonce, v, hexlify(r), hexlify(s));

      // Check authorization state after
      const authStateAfter = await debtToken.authorizationState(authorizer, nonce);
      assert.isTrue(authStateAfter);

      // Check event
      const receipt = await tx.wait();
      const event = receipt.events.find((e) => e.event === "AuthorizationCanceled");
      assert.equal(event.args.authorizer, authorizer);
      assert.equal(event.args.nonce, nonce);
    });

    it("should revert when canceling already used authorization", async () => {
      const from = alice.address;
      const to = bob.address;
      const value = toBN(dec(100, 18));
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

    it("should revert with invalid signature", async () => {
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

      // Sign with wrong key
      const { v, r, s } = sign(digest, bobPrivateKey);

      await assertRevert(
        debtToken.cancelAuthorization(authorizer, nonce, v, hexlify(r), hexlify(s)),
        "DebtToken: invalid signature",
      );
    });
  });

  describe("authorizationState", () => {
    it("should return false for unused nonce", async () => {
      const nonce = randomBytes(32);
      const state = await debtToken.authorizationState(alice.address, nonce);
      assert.isFalse(state);
    });

    it("should return true for used nonce", async () => {
      const from = alice.address;
      const to = bob.address;
      const value = toBN(dec(50, 18));
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
      assert.isTrue(state);
    });
  });

  describe("Gas optimization", () => {
    it("should have reasonable gas costs for transfers", async () => {
      const from = alice.address;
      const to = bob.address;
      const value = toBN(dec(100, 18));
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
      console.log(`transferWithAuthorization gas used: ${receipt.gasUsed}`);

      // Gas should be reasonable (less than 100k)
      assert.isTrue(receipt.gasUsed.lt(100000));
    });
  });
});
