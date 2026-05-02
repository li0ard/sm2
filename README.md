<p align="center">
    <b>@li0ard/sm2</b><br>
    <b>SM2 curves and DSA in pure TypeScript</b>
    <br>
    <a href="https://li0ard.is-cool.dev/sm2">docs</a>
    <br><br>
    <a href="https://github.com/li0ard/sm2/actions/workflows/test.yml"><img src="https://github.com/li0ard/sm2/actions/workflows/test.yml/badge.svg" /></a>
    <a href="https://github.com/li0ard/sm2/blob/main/LICENSE"><img src="https://img.shields.io/github/license/li0ard/sm2" /></a>
    <br>
    <a href="https://npmjs.com/package/@li0ard/sm2"><img src="https://img.shields.io/npm/v/@li0ard/sm2" /></a>
    <a href="https://jsr.io/@li0ard/sm2"><img src="https://jsr.io/badges/@li0ard/sm2" /></a>
    <br>
    <hr>
</p>

## Installation

```bash
# from NPM
npm i @li0ard/sm2

# from JSR
bunx jsr i @li0ard/sm2
```

## Supported modes:
- [x] DSA
- [x] Key exchange
- [x] Encryption schema

## Features
- Provides simple and modern API
- Most of the APIs are strictly typed
- Fully complies with [GB/T 32918-2016](https://github.com/alipay/tls13-sm-spec/blob/master/sm-en-pdfs/sm2/GBT.32918.2-2016.SM2-en.pdf) standard
- Supports Bun, Node.js, Deno, Browsers

## Examples
### Create signature
```ts
import { sign } from "@li0ard/sm2";

const privateKey = hexToBytes("39...B8");
const message = hexToBytes("6D65737361676520646967657374");

console.log(sign(privateKey, message));
```