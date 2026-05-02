import { describe, test, expect } from "bun:test";
import { hexToBytes } from "@noble/curves/utils.js";
import { CipherMode, decrypt, encrypt } from "../src";

const privateKey = hexToBytes("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
const publicKey = hexToBytes("0409F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13");
const message = hexToBytes("656E6372797074696F6E207374616E64617264");
const random = hexToBytes("59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21");
const ciphertext = hexToBytes("0404EBFC718E8D1798620432268E77FEB6415E2EDE0E073C0F4F640ECD2E149A73E858F9D81E5430A57B36DAAB8F950A3C64E6EE6A63094D99283AFF767E124DF059983C18F809E262923C53AEC295D30383B54E39D609D160AFCB1908D0BD876621886CA989CA9C7D58087307CA93092D651EFA");

describe("Cipher", () => {
    test("Encryption", () => expect(encrypt(publicKey, message, CipherMode.C1C3C2, random)).toStrictEqual(ciphertext));
    test("Decryption", () => {
        expect(decrypt(privateKey, ciphertext)).toStrictEqual(message);

        const encrypted = encrypt(publicKey, message);
        expect(decrypt(privateKey, encrypted)).toStrictEqual(message);
    });
});