// Only immutable raw corpus bytes are retained between calls. Every operation
// receives distinct caller-owned arrays and a newly constructed options object.
export const fresh = (bytes) => Uint8Array.from(bytes);
export function invokeFresh(alg, op, c) {
  switch (op) {
    case 'keygen': return alg.keygen(fresh(c.seed));
    case 'getPublicKey': return alg.getPublicKey(fresh(c.secretKey));
    case 'sign': return alg.sign(fresh(c.message), fresh(c.secretKey), { context: fresh(c.context), extraEntropy: false });
    case 'verify': return alg.verify(fresh(c.signature), fresh(c.message), fresh(c.publicKey), { context: fresh(c.context) });
    default: throw Error(`unknown operation: ${op}`);
  }
}
export function decodeCase(c) {
  return Object.fromEntries(Object.entries(c).map(([k, v]) =>
    [k, ['seed', 'secretKey', 'publicKey', 'message', 'context', 'signature'].includes(k) ? Uint8Array.from(Buffer.from(v, 'hex')) : v]));
}
export function expected(c, op) {
  return op === 'keygen' ? { publicKey: c.publicKey, secretKey: c.secretKey }
    : op === 'getPublicKey' ? c.publicKey : op === 'sign' ? c.signature : true;
}
