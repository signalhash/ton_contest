import { Blockchain, SandboxContract, TreasuryContract } from "@ton/sandbox";
import { Address, toNano, fromNano, comment, beginCell, Slice, DictionaryKey, Dictionary, DictionaryValue } from "@ton/core";
import { Cell } from "@ton/core";
import { PayoutVault } from "./output/contest_PayoutVault";
import nacl from "tweetnacl";
import crypto from "crypto";
import "@ton/test-utils";
import { on } from "events";

const ton = (x: number | string) => toNano(x.toString());

const OP_ALLOC_V1 = 0xa110c8;
const OP_WITHDRAW_V1 = 0x5717d2;
const OP_MASTER_V1 = 0x555cdf;

const MIN_RENT_RESERVE = 50_000_000n;

const test_username = "user-abc-0001";

const UintArrayToBigInt = (b: Uint8Array) => BigInt("0x" + Buffer.from(b).toString("hex"));
const UintArrayToSha256 = (buf: Uint8Array) => UintArrayToBigInt(crypto.createHash("sha256").update(buf).digest());
const TextToSha256 = (txt: string) => UintArrayToSha256(Buffer.from(txt, "utf8"));

const toSlice = (bytes: Buffer | Uint8Array) =>
    beginCell()
        .storeBuffer(Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes))
        .endCell()
        .beginParse();

const BigEndianToBigInt = (b: Uint8Array | Buffer) => [...Buffer.from(b)].reduce((a, c) => (a << 8n) + BigInt(c), 0n);

function buildAllocPayload(refCell: Dictionary<bigint, bigint>, validUntil: number, prevHash: bigint) {
    const b = beginCell();
    refCell.store(b);
    b.storeUint(validUntil, 32);
    b.storeUint(prevHash, 256);
    return b.endCell().hash();
}

function buildWithdrawPayload(userKey: bigint, to: Address, validUntil: number, prevHash: bigint) {
    const b = beginCell();
    b.storeUint(userKey, 256);
    b.storeUint(validUntil, 32);
    b.storeAddress(to);
    b.storeUint(prevHash, 256);
    return b.endCell().hash();
}

function buildSetKeyPayload(newKey: bigint, prevHash: bigint) {
    const b = beginCell();
    b.storeUint(newKey, 256);
    b.storeUint(prevHash, 256);
    return b.endCell().hash();
}


type Item = { userId: bigint; delta: bigint };

const DELTA_BITS = 128;

// ---- very small codecs (must match your Tact struct) ----
const Key256 = Dictionary.Keys.BigUint(256);
const ValN = {
  serialize: (src: bigint, b: any) => b.storeUint(src, DELTA_BITS),
  parse: (p: any) => p.loadUintBig(DELTA_BITS),
};

// 1) Build the dictionary (aggregates duplicates, validates ranges)
export function buildItemsDictionary(items: Item[]): Dictionary<bigint, bigint> {
  const dict = Dictionary.empty<bigint, bigint>(Key256, ValN);

  for (const { userId, delta } of items) {
    dict.set(userId, delta);
  }
  return dict;
}

describe("SignalHashContest", () => {
    let blockchain: Blockchain;

    let owner: SandboxContract<TreasuryContract>;
    let funding: SandboxContract<TreasuryContract>;
    let receiver: SandboxContract<TreasuryContract>;

    let vault: SandboxContract<PayoutVault>;

    let masterPriv: Uint8Array;
    let masterPub: Uint8Array;
    let masterPubKeyBig: bigint;

    beforeAll(async () => {
        blockchain = await Blockchain.create();
    });

    beforeEach(async () => {
        owner = await blockchain.treasury("owner");
        funding = await blockchain.treasury("funding");
        receiver = await blockchain.treasury("receiver");

        // --- Ed25519 master key (public goes on-chain as uint256) ---
        const seed32 = new Uint8Array(crypto.randomBytes(32));
        const kp = nacl.sign.keyPair.fromSeed(seed32);
        masterPriv = kp.secretKey;
        masterPub = kp.publicKey;

        masterPubKeyBig = BigEndianToBigInt(kp.publicKey);

        const init = await PayoutVault.fromInit(owner.address as Address, masterPubKeyBig);

        // --- Open & deploy the contract ---
        vault = blockchain.openContract(init);

        await owner.send({
            to: vault.address,
            value: toNano("0.2"),
            init: init.init,
        });

        await funding.send({
            to: vault.address,
            value: toNano("5"),
        });

        const acc = await blockchain.getContract(vault.address);
    });

    it("allocates for a user and withdraws FULL amount when vault can cover it", async () => {
        const userKey = TextToSha256(test_username);

        const validUntil = Math.floor(Date.now() / 1000) + 3600;

        // head hash should be 0 initially
        expect(await vault.getGetHeadHash()).toEqual(0n);
        expect(await vault.getGetMasterPubKey()).toEqual(masterPubKeyBig);
        // ---------- AddAllocation (owner internal + master signature) ----------
        {
            const delta = toNano("1.5"); // 1.5 TON

            let itemsCell = buildItemsDictionary([
                {
                    userId: TextToSha256(test_username),
                    delta: delta,
                },
                {
                    userId: TextToSha256(test_username + "1"),
                    delta: delta,
                },
                {
                    userId: TextToSha256(test_username + "3"),
                    delta: delta,
                },
                {
                    userId: TextToSha256(test_username + "4"),
                    delta: delta,
                },
                {
                    userId: TextToSha256(test_username + "5"),
                    delta: delta,
                },
            ]);

            const payloadSlice = buildAllocPayload(itemsCell, validUntil, 0n);
            const sig = nacl.sign.detached(payloadSlice, masterPriv);

            var tx1 = await vault.send(
                owner.getSender(),
                {
                    value: ton("0.01"),
                    bounce: false,
                },
                {
                    $$type: "AddAllocation",
                    signature: toSlice(sig),
                    body: {
                        $$type: "AddAllocationBody",
                        items: itemsCell,
                        validUntil: BigInt(validUntil),
                        prevHash: 0n                       
                    },
                }
            );

            tx1.transactions.forEach((tx: any) => {
                // Quick summary
                console.log('totalFees:', tx.totalFees);

                // Detailed breakdown (if present in sandbox objects)
                const d = tx.description;
                if (d?.computePhase) {
                console.log('gas used:', d.computePhase.gasUsed);
                }
                if (d?.actionPhase) {
                console.log('fwd fees:', d.actionPhase.totalFwdFees);
                console.log('action success:', d.actionPhase.success);
                }
                if (d?.storagePhase) {
                console.log('storage written:', d.storagePhase.status, d.storagePhase.storageFeesCollected);
                }
            });

            const balAfterAlloc = await vault.getGetAvailableById(TextToSha256(test_username));
            expect(balAfterAlloc).toEqual(delta);
        }

        // ---------- Withdraw (external + master signature) ----------
        {
            const head1 = await vault.getGetHeadHash();

            const payloadSlice = buildWithdrawPayload(userKey, receiver.address as Address, validUntil, head1);
            const sig = nacl.sign.detached(payloadSlice, masterPriv);

            // track user balance before
            const uBefore = (await blockchain.getContract(receiver.address)).balance;

            var tx = await vault.sendExternal({
                $$type: "Withdraw",
                signature: toSlice(sig),
                body: {
                    $$type: "WithdrawBody",
                    userId: TextToSha256(test_username),
                    validUntil: BigInt(validUntil),
                    to: receiver.address,
                    prevHash: head1,
                },
            });

            const uAfter = (await blockchain.getContract(receiver.address)).balance;

            expect(uAfter - uBefore + ton("0.001") >= toNano("1.5")).toBeTruthy();

            const balAfter = await vault.getGetAvailableById(TextToSha256(test_username));
            expect(balAfter).toBeNull();
        }
    });

    it("rejects withdraw if vault cannot cover FULL amount (rent reserve honored)", async () => {
        const userKey = TextToSha256(test_username);
        const validUntil = Math.floor(Date.now() / 1000) + 3600;

        {
            const delta = toNano("4.9");

            let itemsCell = buildItemsDictionary([
                {
                    userId: TextToSha256(test_username),
                    delta: delta,
                }
            ]);

            const payloadSlice = buildAllocPayload(itemsCell, validUntil, 0n);
            const sig = nacl.sign.detached(payloadSlice, masterPriv);

            var tx = await vault.send(
                owner.getSender(),
                {
                    value: ton("0.05"),
                    bounce: true,
                },
                {
                    $$type: "AddAllocation",
                    signature: toSlice(sig),
                    body: {
                        $$type: "AddAllocationBody",
                        items: itemsCell,
                        prevHash: 0n,
                        validUntil: BigInt(validUntil),
                    },
                }
            );
        }

        {
            const head = await vault.getGetHeadHash();
            const payloadSlice = buildWithdrawPayload(userKey, receiver.address as Address, validUntil, head);
            const sig = nacl.sign.detached(payloadSlice, masterPriv);

            await vault.sendExternal({
                $$type: "Withdraw",
                signature: toSlice(sig),
                body: {
                    $$type: "WithdrawBody",
                    userId: TextToSha256(test_username),
                    validUntil: BigInt(validUntil),
                    to: receiver.address,
                    prevHash: head,
                },
            });
        }

        {
            const head = await vault.getGetHeadHash();
            const delta = toNano("2");

            let itemsCell = buildItemsDictionary([
                {
                    userId: TextToSha256(test_username),
                    delta: delta,
                }
            ]);


            const payloadSlice = buildAllocPayload(itemsCell, validUntil, head);
            const sig = nacl.sign.detached(payloadSlice, masterPriv);

            var tx = await vault.send(
                owner.getSender(),
                {
                    value: ton("0.05"),
                    bounce: true,
                },
                {
                    $$type: "AddAllocation",
                    signature: toSlice(sig),
                    body: {
                        $$type: "AddAllocationBody",
                        items: itemsCell,
                        prevHash: head,
                        validUntil: BigInt(validUntil),
                    },
                }
            );

            const vaultBalance = (await blockchain.getContract(vault.address)).balance;
            const keep = MIN_RENT_RESERVE + toNano("0.05"); // keep rent + tiny safety
            const withdrawable = vaultBalance - keep;

            const head2 = await vault.getGetHeadHash();
            const payloadSlice2 = buildWithdrawPayload(userKey, receiver.address as Address, validUntil, head2);
            const sig2 = nacl.sign.detached(payloadSlice2, masterPriv);

            await expect(
                vault.sendExternal({
                    $$type: "Withdraw",
                    signature: toSlice(sig2),
                    body: {
                        $$type: "WithdrawBody",
                        userId: TextToSha256(test_username),
                        validUntil: BigInt(validUntil),
                        to: receiver.address,
                        prevHash: head2,
                    },
                })
            ).rejects.toThrow(/terminating vm with exit code 52649/i);
        }
    });

    it("owner-only SetMasterPubKey, with signature by current master", async () => {
        const nSeed32 = new Uint8Array(crypto.randomBytes(32));

        const nKp = nacl.sign.keyPair.fromSeed(nSeed32);
        const newPubBig = BigEndianToBigInt(nKp.publicKey);

        // payload signed by *current* master key
        const payloadSlice = buildSetKeyPayload(newPubBig, 0n);
        const sig = nacl.sign.detached(payloadSlice, masterPriv);

        var tx = await vault.send(
            owner.getSender(),
            {
                value: ton("0.01"),
                bounce: false,
            },
            {
                $$type: "SetMasterPubKey",
                signature: toSlice(sig),
                body: {
                    $$type: "SetMasterPubKeyBody",
                    newMasterPubKey: newPubBig,
                    prevHash: 0n,
                },
            }
        );

        const vaultId = BigInt("0x" + Buffer.from(vault.address.hash).toString("hex"));
        const vaultTx: any = tx.transactions.find((t) => t.address === vaultId);
        console.log(vaultTx.totalFees);

        // head advanced
        const head1 = await vault.getGetHeadHash();
        expect(head1).not.toEqual(0n);

        const onchainKey = await vault.getGetMasterPubKey();
        expect(onchainKey).toEqual(newPubBig);
    });

    it("rejects replay (prevHash mismatch)", async () => {
        const userKey = TextToSha256(test_username);
        const validUntil = Math.floor(Date.now() / 1000) + 3600;

        const delta = toNano("1");

        let itemsCell = buildItemsDictionary([
                {
                    userId: TextToSha256(test_username),
                    delta: delta,
                }
            ]);


        // Build allocation once
        const payloadSlice = buildAllocPayload(itemsCell, validUntil, 0n);
        const sig = nacl.sign.detached(payloadSlice, masterPriv);

        var tx = await vault.send(
            owner.getSender(),
            {
                value: ton("0.05"),
                bounce: true,
            },
            {
                $$type: "AddAllocation",
                signature: toSlice(sig),
                body: {
                    $$type: "AddAllocationBody",
                    prevHash: 0n,
                    validUntil: BigInt(validUntil),
                    items: itemsCell,
                },
            }
        );

        const head0 = await vault.getGetHeadHash();

        var tx2 = await vault.send(
            owner.getSender(),
            {
                value: ton("0.05"),
                bounce: false,
            },
            {
                $$type: "AddAllocation",
                signature: toSlice(sig),
                body: {
                    $$type: "AddAllocationBody",
                    items: itemsCell,
                    prevHash: 0n,
                    validUntil: BigInt(validUntil),
                },
            }
        );

        const vaultId = BigInt("0x" + Buffer.from(vault.address.hash).toString("hex"));
        const vaultTx: any = tx2.transactions.find((t) => t.address === vaultId);
        console.log(vaultTx.totalFees);

        expect(vaultTx).toBeDefined();
        expect(BigInt(vaultTx!.totalFees.coins)).toBeLessThan(1_500_000n);
        expect(vaultTx!.description.aborted).toBe(true);

        // Also assert head didn’t change:
        const headAfterFail = await vault.getGetHeadHash();
        expect(headAfterFail).toEqual(head0);
    });
});
