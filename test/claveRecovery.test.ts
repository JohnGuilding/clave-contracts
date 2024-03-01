/**
 * Copyright Clave - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */
import type { Contract } from "@ethersproject/contracts";
import { expect } from "chai";
import type { ec } from "elliptic";
import { AbiCoder, concat, parseEther, BigNumberish, keccak256 } from "ethers";
import { Provider, Wallet, utils } from "zksync-ethers";

import type {
  AccountFactory,
  BatchCaller,
  ClaveImplementation,
  ClaveRegistry,
  P256VerifierExpensive,
  TEEValidator,
} from "../typechain-types";
import {
  deployAccount,
  deployBatchCaller,
  deployFactory,
  deployImplementation,
  deployMockDKIMRegsitry,
  deployMockGroth16Verifier,
  deployEmailRecoveryModule,
  deployRegistry,
  deployTeeValidator,
  deployVerifier,
} from "./utils/deploy";
import { encodePublicKey, genKey } from "./utils/p256";
import type { CallableProxy } from "./utils/proxy-helpers";
import { richWallets } from "./utils/rich-wallets";
import { prepareTeeTx } from "./utils/transaction";

const richPk = richWallets[0].privateKey;

let provider: Provider;
let richWallet: Wallet;

let keyPair: ec.KeyPair;

let batchCaller: BatchCaller;
let verifier: P256VerifierExpensive;
let teeValidator: TEEValidator;
let implementation: ClaveImplementation;
let factory: AccountFactory;
let account: CallableProxy;
let registry: ClaveRegistry;

async function getNonce(wallet: Wallet): Promise<number> {
  return await wallet.getNonce();
}

async function getContractNonce(account: Contract | unknown): Promise<number> {
  return await provider.getTransactionCount(
    await (account as Contract).getAddress()
  );
}

async function waitTillNonceUpdate(
  wallet: Wallet,
  nonce: number
): Promise<void> {
  while ((await wallet.getNonce()) === nonce) {
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
}

async function waitTillNonceUpdateContract(
  account: Contract | unknown,
  nonce: number
): Promise<void> {
  while (
    (await provider.getTransactionCount(
      await (account as Contract).getAddress()
    )) === nonce
  ) {
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
}

beforeEach(async () => {
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  provider = new Provider(hre.network.config.url);
  richWallet = new Wallet(richPk, provider);

  keyPair = genKey();
  const publicKey = encodePublicKey(keyPair);

  let nonce = await getNonce(richWallet);
  batchCaller = await deployBatchCaller(richWallet);
  await waitTillNonceUpdate(richWallet, nonce);
  nonce = await getNonce(richWallet);
  verifier = await deployVerifier(richWallet);
  await waitTillNonceUpdate(richWallet, nonce);
  nonce = await getNonce(richWallet);
  teeValidator = await deployTeeValidator(
    richWallet,
    await verifier.getAddress()
  );
  await waitTillNonceUpdate(richWallet, nonce);
  nonce = await getNonce(richWallet);
  implementation = await deployImplementation(
    richWallet,
    await batchCaller.getAddress()
  );
  await waitTillNonceUpdate(richWallet, nonce);
  nonce = await getNonce(richWallet);
  registry = await deployRegistry(richWallet);
  await waitTillNonceUpdate(richWallet, nonce);
  nonce = await getNonce(richWallet);
  factory = await deployFactory(
    richWallet,
    await implementation.getAddress(),
    await registry.getAddress()
  );
  await waitTillNonceUpdate(richWallet, nonce);
  nonce = await getNonce(richWallet);
  await registry.setFactory(await factory.getAddress());
  await waitTillNonceUpdate(richWallet, nonce);
  nonce = await getNonce(richWallet);
  account = await deployAccount(
    richWallet,
    await richWallet.getNonce(),
    factory,
    await teeValidator.getAddress(),
    publicKey
  );
  await waitTillNonceUpdate(richWallet, nonce);
  nonce = await getNonce(richWallet);
  // 100 ETH transfered to Account
  await (
    await richWallet.sendTransaction({
      to: await account.getAddress(),
      value: parseEther("100"),
    })
  ).wait();
  await waitTillNonceUpdate(richWallet, nonce);
});

describe("Account recovery no module no hook TEE validator", function () {
  describe("Module manager", function () {
    describe("Should not revert when", function () {
      it("Adds a new module correctly", async function () {
        // deploy recovery module
        let richWalletNonce = await getNonce(richWallet);
        const verifier = await deployMockGroth16Verifier(richWallet);
        await waitTillNonceUpdate(richWallet, richWalletNonce);

        richWalletNonce = await getNonce(richWallet);
        const defaultDkimRegistry = await deployMockDKIMRegsitry(richWallet);
        await waitTillNonceUpdate(richWallet, richWalletNonce);

        richWalletNonce = await getNonce(richWallet);
        const recoveryModule = await deployEmailRecoveryModule(
          richWallet,
          verifier,
          defaultDkimRegistry
        );
        await waitTillNonceUpdate(richWallet, richWalletNonce);

        expect(await account.isModule(await recoveryModule.getAddress())).to.be
          .false;

        // init module
        const timeLock = 2;
        const threshold = 1;
        const abiCoder = AbiCoder.defaultAbiCoder();
        const guardianHash = keccak256(
          abiCoder.encode(["string"], ["mockGuardianHash"])
        );
        const guardianHashes = [guardianHash];

        const initData = abiCoder.encode(
          ["uint128", "uint128", "bytes32[]"],
          [timeLock, threshold, guardianHashes]
        );
        const moduleAndData = concat([
          await recoveryModule.getAddress(),
          initData,
        ]);

        const addModuleTx =
          await account.addModule.populateTransaction(moduleAndData);

        const tx = await prepareTeeTx(
          provider,
          account,
          addModuleTx,
          await teeValidator.getAddress(),
          keyPair
        );

        let accountNonce = await getContractNonce(account);
        const txReceipt = await provider.broadcastTransaction(
          utils.serializeEip712(tx)
        );
        await txReceipt.wait();
        await waitTillNonceUpdateContract(account, accountNonce);

        expect(await account.isModule(await recoveryModule.getAddress())).to.be
          .true;

        const expectedModules = [await recoveryModule.getAddress()];

        expect(await account.listModules()).to.deep.eq(expectedModules);

        // start recovery
        const newKeyPair = genKey();
        const newPublicKey = encodePublicKey(newKeyPair);
        const recoveryData = {
          recoveringAddress: await account.getAddress(),
          newOwner: newPublicKey,
          nonce: 0,
        };

        const dkimPublicKeyHash = keccak256(
          abiCoder.encode(["string"], ["mockDkimPublicKeyHash"])
        );
        type GuardianData = {
          guardianHash: string;
          dkimPublicKeyHash: string;
          emailDomain: string;
          a: [BigNumberish, BigNumberish];
          b: [[BigNumberish, BigNumberish], [BigNumberish, BigNumberish]];
          c: [BigNumberish, BigNumberish];
        }[];
        const guardianData: GuardianData = [
          {
            guardianHash: guardianHash,
            dkimPublicKeyHash: dkimPublicKeyHash,
            emailDomain: "google.com",
            a: [0, 0],
            b: [
              [0, 0],
              [0, 0],
            ],
            c: [0, 0],
          },
        ];

        const recoveryStateBefore = await recoveryModule.recoveryStates(
          await account.getAddress()
        );
        expect(recoveryStateBefore.newOwner).to.not.equal(newPublicKey);

        richWalletNonce = await getNonce(richWallet);
        const startRecoveryTx = await recoveryModule.startRecovery(
          recoveryData,
          guardianData,
          { gasLimit: 80000000n }
        );
        await startRecoveryTx.wait();
        await waitTillNonceUpdate(richWallet, richWalletNonce);

        const recoveryStateAfter = await recoveryModule.recoveryStates(
          await account.getAddress()
        );
        expect(recoveryStateAfter.newOwner).to.equal(newPublicKey);

        // execute recovery
        const oldOwners = await account.r1ListOwners();
        expect(oldOwners.length).to.equal(1);
        expect(oldOwners[0]).to.not.equal(newPublicKey);

        const blockTimestamp = (await provider.getBlock("latest")).timestamp;
        if (recoveryStateAfter.timelockExpiry <= blockTimestamp) {
          throw new Error("Wait more time");
        }

        const executeRecovery = await recoveryModule.executeRecovery(
          await account.getAddress()
        );
        await executeRecovery.wait();

        const newOwners = await account.r1ListOwners();
        expect(newOwners.length).to.equal(1);
        expect(newOwners[0]).to.equal(newPublicKey);
      });
    });
  });
});
