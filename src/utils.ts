import { SM3 } from "@li0ard/sm3";
import { numberToBytesBE, numberToVarBytesBE, type TArg, type TRet } from "@noble/curves/utils.js";
import { SIZE, SM2p256 } from "./const.js";

export const xorBytes = (a: TArg<Uint8Array>, b: TArg<Uint8Array>): TRet<Uint8Array> => {
    const mlen = Math.min(a.length, b.length);
    const result = new Uint8Array(mlen);
    for(let i = 0; i < mlen; i++) result[i] = a[i] ^ b[i];

    return result;
}

export const Z = (publicKey: TArg<Uint8Array>, uid: TArg<Uint8Array>): TRet<Uint8Array> => {
    const za = new SM3();
    const pk = SM2p256.fromBytes(publicKey);

    const uidLen = uid.length;
    if(uidLen >= 8192) throw new Error("UID too large");

    const entla = 8 * uidLen;
    za.update(numberToBytesBE(entla, 2));
    if(uidLen > 0) za.update(uid);

    za.update(numberToBytesBE(SM2p256.CURVE().a, SIZE));
    za.update(numberToBytesBE(SM2p256.CURVE().b, SIZE));
    za.update(numberToBytesBE(SM2p256.CURVE().Gx, SIZE));
    za.update(numberToBytesBE(SM2p256.CURVE().Gy, SIZE));
    za.update(numberToVarBytesBE(pk.x));
    za.update(numberToVarBytesBE(pk.y));
    
    return za.digest();
}