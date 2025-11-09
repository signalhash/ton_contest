import * as fs from "fs";
import * as path from "path";
import * as dotenv from "dotenv";
import { Address, contractAddress } from "@ton/core";
import { PayoutVault } from "./output/contest_PayoutVault";
import { prepareTactDeployment } from "@tact-lang/deployer";
import nacl from "tweetnacl";
import crypto from "crypto";

dotenv.config();

const NETWORK = (process.env.NETWORK || "testnet") as "testnet" | "mainnet";
const BigEndianToBigInt = (b: Uint8Array | Buffer) => [...Buffer.from(b)].reduce((a, c) => (a << 8n) + BigInt(c), 0n);

(async (): Promise<void> => {

    let packageName = "contest_PayoutVault.pkg";
    let owner = Address.parse(process.env.OWNER_ADDRESS ?? '');

    const seed32 = new Uint8Array(crypto.randomBytes(32));
    const kp = nacl.sign.keyPair.fromSeed(seed32);
    const masterPub = BigEndianToBigInt(kp.publicKey);
    let init = await PayoutVault.init(owner, masterPub);
    const secret =  BigEndianToBigInt(kp.secretKey)

    // Load required data
    let address = contractAddress(0, init);
    let data = init.data.toBoc();
    let pkg = fs.readFileSync(path.resolve(__dirname, "output", packageName));

    // Prepareing
    console.log("Uploading package...");
    let prepare = await prepareTactDeployment({ pkg, data, testnet: NETWORK == "testnet" });

    // Deploying
    console.log("============================================================================================");
    console.log("Secret Key")
    console.log("============================================================================================");
    console.log(secret);
    console.log();
    console.log("============================================================================================");
    console.log("Contract Address");    
    console.log("============================================================================================");
    console.log();
    console.log(address.toString({ testOnly: NETWORK == "testnet"  }));
    console.log();
    console.log("============================================================================================");
    console.log("Please, follow deployment link");
    console.log("============================================================================================");
    console.log();
    console.log(prepare);
    console.log();
    console.log("============================================================================================");
})();
