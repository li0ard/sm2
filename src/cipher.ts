import { bytesToNumberBE, concatBytes, equalBytes, numberToBytesBE, type TArg, type TRet } from "@noble/curves/utils.js";
import { generateEphemeralKey } from "./index.js";
import { CipherMode, SIZE, SM2p256, _4 } from "./const.js";
import { sm3, sm3_kdf } from "@li0ard/sm3";
import { xorBytes } from "./utils.js";

/** 
 * Encrypt message with public key
 * @param publicKey Public key
 * @param data Message (data) to encrypt
 * @param mode Cipher mode (Optional)
 * @param rand Predefined random data (Optional)
 */
export const encrypt = (
    publicKey: TArg<Uint8Array>,
    data: TArg<Uint8Array>,
    mode: CipherMode = CipherMode.C1C3C2,
    rand?: TArg<Uint8Array>
): TRet<Uint8Array> => {
    const k = bytesToNumberBE(generateEphemeralKey(rand));
    const pk_p = SM2p256.fromBytes(publicKey);
    pk_p.assertValidity();

    const {x: x1, y: y1} = SM2p256.BASE.multiply(k);
    const {x: x2, y: y2} = pk_p.multiply(k);
    const x2Buf = numberToBytesBE(x2, SIZE);
    const y2Buf = numberToBytesBE(y2, SIZE);

    const C1 = concatBytes(numberToBytesBE(x1, SIZE), numberToBytesBE(y1, SIZE));
    const C2 = xorBytes(data, sm3_kdf(concatBytes(x2Buf, y2Buf), data.length));
    const C3 = sm3(concatBytes(x2Buf, data, y2Buf));
    
    switch(mode) {
        case CipherMode.C1C3C2:
            return concatBytes(_4, C1, C3, C2);
        case CipherMode.C1C2C3:
            return concatBytes(_4, C1, C2, C3);
    }
}

/**
 * Decrypt message with private key
 * @param privateKey Private key
 * @param ciphertext Ciphertext
 * @param mode Cipher mode (Optional)
 */
export const decrypt = (
    privateKey: TArg<Uint8Array>,
    ciphertext: TArg<Uint8Array>,
    mode: CipherMode = CipherMode.C1C3C2
): TRet<Uint8Array> => {
    if (ciphertext.length < 97) throw new Error("Ciphertext too short");
    if (ciphertext[0] !== 0x04) throw new Error("Invalid C1 prefix (expected 0x04)");
    const C1 = ciphertext.subarray(1, 65);
    const c2Len = ciphertext.length - 97;

    let C2: Uint8Array;
    let C3: Uint8Array;
    switch (mode) {
        case CipherMode.C1C3C2:
            C3 = ciphertext.subarray(65, 97);
            C2 = ciphertext.subarray(97);
            break;

        case CipherMode.C1C2C3:
            C2 = ciphertext.subarray(65, 65 + c2Len);
            C3 = ciphertext.subarray(65 + c2Len);
            break;
    }

    const {x:x2, y:y2} = SM2p256.fromBytes(concatBytes(_4, C1))
        .multiply(bytesToNumberBE(privateKey));
    const x2Buf = numberToBytesBE(x2, SIZE);
    const y2Buf = numberToBytesBE(y2, SIZE);

    const M = xorBytes(C2, sm3_kdf(concatBytes(x2Buf, y2Buf), C2.length));
    if(!equalBytes(C3, sm3(concatBytes(x2Buf, M, y2Buf))))
        throw new Error("Invalid ciphertext: integrity check failed");

    return M;
}