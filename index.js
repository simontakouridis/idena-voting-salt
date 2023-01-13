import sha3 from 'js-sha3';
import secp256k1 from 'secp256k1';

let contractHash;
let epoch;
let privateKey;

process.argv.forEach(function (val, index) {
  switch (index) {
    case 2:
      contractHash = val;
      break;
    case 3:
      epoch = val;
      break;
    case 4:
      privateKey = val;
      break;
  }
});

if (!contractHash || !epoch || !privateKey) {
  console.log('Arguments not provided');
  process.exit();
}

const salt = toHexString(
  dnaSign(`salt-${contractHash}-${epoch}`, privateKey),
  true
);

console.log(`Idena voting salt: ${salt}`);

function toHexString(byteArray, withPrefix) {
  return (
    (withPrefix ? '0x' : '') +
    Array.from(byteArray, function(byte) {
      // eslint-disable-next-line no-bitwise
      return `0${(byte & 0xff).toString(16)}`.slice(-2)
    }).join('')
  )
}

function dnaSign(data, key) {
  const hash = sha3.keccak_256.array(data)
  const hash2 = sha3.keccak_256.array(hash)

  const {signature, recid} = secp256k1.ecdsaSign(
    new Uint8Array(hash2),
    typeof key === 'string' ? hexToUint8Array(key) : new Uint8Array(key)
  )

  return Buffer.from([...signature, recid])
}

function hexToUint8Array(hexString) {
  const str = stripHexPrefix(hexString)

  const arrayBuffer = new Uint8Array(str.length / 2)

  for (let i = 0; i < str.length; i += 2) {
    const byteValue = parseInt(str.substr(i, 2), 16)
    arrayBuffer[i / 2] = byteValue
  }

  return arrayBuffer
}

function stripHexPrefix(str) {
  if (typeof str !== 'string') {
    return str
  }
  return isHexPrefixed(str) ? str.slice(2) : str
}

function isHexPrefixed(str) {
  return str.slice(0, 2) === '0x'
}
