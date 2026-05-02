import { describe, test, expect } from "bun:test";
import { hexToBytes } from "@noble/curves/utils.js";
import { DEFAULT_UID, getPublicKey, sign, verify } from "../src";

const privateKey = hexToBytes("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
const publicKey = hexToBytes("0409F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13");
const message = hexToBytes("6D65737361676520646967657374");
const rand = hexToBytes("59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21");
const signature = hexToBytes("F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3B1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA");

describe("Signatures", () => {
    test("Get public key", () => expect(getPublicKey(privateKey)).toStrictEqual(publicKey));
    test("Sign", () => expect(sign(privateKey, message, DEFAULT_UID, rand)).toStrictEqual(signature));
    test("Verify", () => {
        expect(verify(publicKey, message, signature)).toBeTrue();

        const randomSignature = sign(privateKey, message);
        expect(verify(publicKey, message, randomSignature)).toBeTrue();
    });
});