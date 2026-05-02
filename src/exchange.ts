import { bytesToNumberBE, concatBytes, numberToVarBytesBE, type TArg } from "@noble/curves/utils.js";
import { _2, _2w, _3, DEFAULT_UID, SM2p256, type ExchangeResult } from "./const.js";
import { getPublicKey } from "./index.js";
import { Z } from "./utils.js";
import { sm3, sm3_kdf } from "@li0ard/sm3";

const keXHat = (x: bigint): bigint => _2w + (x & (_2w - 1n));

const keyExchange = (
    klen: number,
    ida: TArg<Uint8Array>,
    idb: TArg<Uint8Array>,
    privateKey: TArg<Uint8Array>,
    publicKey: TArg<Uint8Array>,
    rpri: TArg<Uint8Array>,
    rpub: TArg<Uint8Array>,
    isA: boolean
): ExchangeResult => {
    const Fn = SM2p256.Fn;
    const priD = bytesToNumberBE(privateKey);
    const rpriD = bytesToNumberBE(rpri);
    const rpri_p = SM2p256.BASE.multiply(rpriD);
    const rpub_p = SM2p256.fromBytes(rpub);
    rpub_p.assertValidity();
    const pub_p = SM2p256.fromBytes(publicKey);
    pub_p.assertValidity();

    const t = Fn.add(priD, keXHat(rpri_p.x) * rpriD);
    const v = pub_p.add(rpub_p.multiply(keXHat(rpub_p.x))).multiply(t);
    v.assertValidity();

    const za = Z(isA ? getPublicKey(privateKey) : publicKey, ida);
    const zb = Z(!isA ? getPublicKey(privateKey) : publicKey, idb);

    const k = sm3_kdf(concatBytes(numberToVarBytesBE(v.x), numberToVarBytesBE(v.y), za, zb), klen);

    const hash = sm3(
        isA ? concatBytes(
            numberToVarBytesBE(v.x),
            za, zb,
            numberToVarBytesBE(rpri_p.x),
            numberToVarBytesBE(rpri_p.y),
            numberToVarBytesBE(rpub_p.x),
            numberToVarBytesBE(rpub_p.y),
        ) : concatBytes(
            numberToVarBytesBE(v.x),
            za, zb,
            numberToVarBytesBE(rpub_p.x),
            numberToVarBytesBE(rpub_p.y),
            numberToVarBytesBE(rpri_p.x),
            numberToVarBytesBE(rpri_p.y),
        )
    );
    const S1 = sm3(concatBytes(_2, numberToVarBytesBE(v.y), hash));
    const S2 = sm3(concatBytes(_3, numberToVarBytesBE(v.y), hash));

    return { k, S1, S2 }
}

/**
 * Key exchange (for side A)
 * @param klen Shared secret length
 * @param privateKeyA Private key (Side A)
 * @param publicKeyB Public key (Side B)
 * @param rpriA Ephemeral private key (Side A)
 * @param rpubB Ephemeral public key (Side B)
 * @param ida Identifier of side A (Optional)
 * @param idb Identifier of side B (Optional)
 */
export const keyExchangeA = (
    klen: number,
    privateKeyA: TArg<Uint8Array>,
    publicKeyB: TArg<Uint8Array>,
    rpriA: TArg<Uint8Array>,
    rpubB: TArg<Uint8Array>,
    ida: TArg<Uint8Array> = DEFAULT_UID,
    idb: TArg<Uint8Array> = DEFAULT_UID,
): ExchangeResult => keyExchange(klen, ida, idb, privateKeyA, publicKeyB, rpriA, rpubB, true);

/**
 * Key exchange (for side B)
 * @param klen Shared secret length
 * @param privateKeyB Private key (Side B)
 * @param publicKeyA Public key (Side A)
 * @param rpriB Ephemeral private key (Side B)
 * @param rpubA Ephemeral public key (Side A)
 * @param ida Identifier of side A (Optional)
 * @param idb Identifier of side B (Optional)
 */
export const keyExchangeB = (
    klen: number,
    privateKeyB: TArg<Uint8Array>,
    publicKeyA: TArg<Uint8Array>,
    rpriB: TArg<Uint8Array>,
    rpubA: TArg<Uint8Array>,
    ida: TArg<Uint8Array> = DEFAULT_UID,
    idb: TArg<Uint8Array> = DEFAULT_UID,
): ExchangeResult =>  keyExchange(klen, ida, idb, privateKeyB, publicKeyA, rpriB, rpubA, false);