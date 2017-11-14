# signcode

[![Travis Build Status](https://travis-ci.org/kevinsawicki/signcode.svg?branch=master)](https://travis-ci.org/kevinsawicki/signcode)
[![js-standard-style](https://img.shields.io/badge/code%20style-standard-brightgreen.svg?style=flat)](http://standardjs.com/)
[![npm](https://img.shields.io/npm/v/signcode.svg)](https://www.npmjs.com/packages/signcode)
[![downloads](https://img.shields.io/npm/dm/signcode.svg)](https://www.npmjs.com/packages/signcode)

Sign Windows executables and installers from a Mac and Linux (`osslsigncode` required).

Works with `.pem`, `.p12`, and `.pfx` code signing files.

Signs with `sha1` and `sha256` signatures by default.

## Installing

```sh
npm install --save-dev signcode
```

## Using

```js
var signcode = require('signcode')

var options = {
  cert: '/Users/kevin/certs/cert.pem',
  key: '/Users/kevin/certs/key.pem',
  overwrite: true,
  path: '/Users/kevin/apps/myapp.exe'
}

signcode.sign(options, function (error) {
  if (error) {
    console.error('Signing failed', error.message)
  } else {
    console.log(options.path + ' is now signed')
  }
})

signcode.verify({ path: '/Users/kevin/apps/myapp.exe' }, function (error) {
  if (error) {
    console.error('Not signed', error.message)
  } else {
    console.log(options.path + ' is signed')
  }
})
```

### Signing Options

| Name           | Type      | Required | Description                 |
| :------------- | :-------- | :------- | :-------------------------- |
| `cert`         | `String`  | Yes      | Path to a certificate file. |
| `path`         | `String`  | Yes      | File path to executable to sign. |
| `hash`         | `Array`   | No       | Signature types to sign the executable with. Defaults to `['sha1', 'sha256']`. |
| `key`          | `String`  | No       | Path to a `.pem` key file. Only required if `cert` is a `.pem` file. |
| `name`         | `String`  | No       | Product name to include in the signature. |
| `overwrite`    | `Boolean` | No       | `true` to sign the executable in place, `false` to write the signed file at the same path but with `-signed` at the end of it. Defaults to `false`. |
| `password`     | `String`  | No       | Password to the certificate or key. |
| `passwordPath` | `String`  | No       | Path to a file containing the password for the certificate or key. |
| `site`         | `String`  | No       | Website URL to include in the signature. |

### Verification Options

| Name           | Type      | Required | Description                 |
| :------------- | :-------- | :------- | :-------------------------- |
| `path`         | `String`  | Yes      | File path to executable to verify. |
| `hash`         | `String`  | No       | Certificate fingerprint to expect on executable. |

### Command Line Example

```sh
signcode sign /Users/kevin/apps/myapp.exe \
  --cert /Users/kevin/certs/cert.p12 \
  --prompt \
  --name 'My App' \
  --url 'http://birthday.pizza'
signcode verify /Users/kevin/apps/myapp.exe
```

Run `signcode -h` to see all the supported options.

## Cert helpers commands

These commands are helpful when working with certificates.

### Create cert and key with no password

```sh
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -nodes
```

### Create cert and key with a password

```sh
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem
```

### Create a p12 with no password

```sh
openssl pkcs12 -export -out ./test/fixtures/cert.p12 -inkey ./test/fixtures/key.pem -in ./test/fixtures/cert.pem
```

### Show fingerprint of a cert

```sh
openssl x509 -noout -in ./test/fixtures/cert.pem -fingerprint -sha1
```

```sh
openssl x509 -noout -in ./test/fixtures/cert.pem -fingerprint -sha256
```
