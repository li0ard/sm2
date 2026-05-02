import { weierstrass } from "@noble/curves/abstract/weierstrass.js";
import { type TRet } from "@noble/curves/utils.js";

export const _2 = new Uint8Array([2]);
export const _3 = new Uint8Array([3]);
export const _4 = new Uint8Array([4]);
export const _2w = 1n << 127n;

export const SM2p256 = weierstrass({
    p: 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFFn,
    a: 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFCn,
    b: 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93n,
    n: 0xfffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123n,
    Gx: 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7n,
    Gy: 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0n,
    h: 1n
});

export const SIZE = 32;

/** Default signer identifier */
export const DEFAULT_UID: TRet<Uint8Array> = new TextEncoder().encode("1234567812345678");

/** Cipher mode */
export enum CipherMode {
    C1C3C2,
    C1C2C3
}

/** Key exchange result */
export interface ExchangeResult {
    /** Shared secret */
    k: TRet<Uint8Array>,
    /** Checksum #1 */
    S1: TRet<Uint8Array>,
    /** Checksum #2 */
    S2: TRet<Uint8Array>
}