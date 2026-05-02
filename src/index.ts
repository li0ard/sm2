import { bytesToNumberBE, concatBytes, numberToBytesBE, numberToVarBytesBE, randomBytes, type TArg, type TRet } from "@noble/curves/utils.js";
import { DEFAULT_UID, SIZE, SM2p256 } from "./const.js";
import { sm3 } from "@li0ard/sm3";
import { Z } from "./utils.js";

/**
 * Generate public key from private
 * @param privateKey Private key
 * @returns {TRet<Uint8Array>} Uncompressed public key in ANSI X9.62 format
 */
export const getPublicKey = (privateKey: TArg<Uint8Array>): TRet<Uint8Array> =>
    SM2p256.BASE.multiply(bytesToNumberBE(privateKey)).toBytes(false);

/**
 * Generate signature of provided message
 * @param privateKey Private key
 * @param msg Message (data) to sign
 * @param uid Signer identifier (aka UID, Optional)
 * @param rand Predefined random data (Optional)
 */
export const sign = (
    privateKey: TArg<Uint8Array>,
    msg: TArg<Uint8Array>,
    uid: TArg<Uint8Array> = DEFAULT_UID,
    rand?: TArg<Uint8Array>
): TRet<Uint8Array> => {
    const za = Z(getPublicKey(privateKey), uid);
    const d = bytesToNumberBE(privateKey);
    const e = bytesToNumberBE(sm3(concatBytes(za, msg)));
    const Fn = SM2p256.Fn;
    
    while(true) {
        const k = bytesToNumberBE(generateEphemeralKey(rand));

        const {x: x1} = SM2p256.BASE.multiply(k);
        const r = Fn.add(e, x1);
        if(r == 0n) continue;

        const s = Fn.mul(
            Fn.inv(Fn.add(1n, d)),
            Fn.sub(k, Fn.mul(r, d))
        );
        if(s == 0n) continue;

        return concatBytes(numberToVarBytesBE(r), numberToVarBytesBE(s));
    }
}

/**
 * Verify signature of provided message
 * @param publicKey Public key
 * @param msg Message (data) to verify
 * @param signature Signature
 * @param uid Signer identifier (aka UID, Optional)
 */
export const verify = (
    publicKey: TArg<Uint8Array>,
    msg: TArg<Uint8Array>,
    signature: TArg<Uint8Array>,
    uid: TArg<Uint8Array> = DEFAULT_UID,
): boolean => {
    if(signature.length != 2 * SIZE) throw new Error("Invalid signature");

    const r = bytesToNumberBE(signature.subarray(0, SIZE));
    const s = bytesToNumberBE(signature.subarray(SIZE));
    if(r <= 0 || r >= SM2p256.CURVE().n || s <= 0 || s >= SM2p256.CURVE().n) return false;

    const za = Z(publicKey, uid);
    const e = bytesToNumberBE(sm3(concatBytes(za, msg)));
    const Fn = SM2p256.Fn;

    const t = Fn.add(r, s);
    if(t == 0n) return false;

    const pk = SM2p256.fromBytes(publicKey);
    const {x: x1} = SM2p256.BASE.multiply(s).add(pk.multiply(t));
    
    const R = Fn.add(e, x1);
    return R == r;
}

/**
 * Generate ephemeral key
 * @param rand Predefined random data (Optional)
 */
export const generateEphemeralKey = (rand?: TArg<Uint8Array>): TRet<Uint8Array> => {
    const Fn = SM2p256.Fn;
    rand ||= randomBytes(SIZE);

    let r: bigint;
    do {
        r = bytesToNumberBE(rand);
    } while (r === 0n || r >= Fn.ORDER);
    
    return numberToBytesBE(r, SIZE);
}


export { DEFAULT_UID, CipherMode, type ExchangeResult } from "./const.js";
export * from "./cipher.js";
export * from "./exchange.js";