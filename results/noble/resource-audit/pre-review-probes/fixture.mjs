import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
const api = await import(pathToFileURL(process.argv[2]));
const hex = (x) => Buffer.from(x).toString('hex');
const rows = [];
for (const parameter of [44, 65, 87]) {
  for (const group of ['warmup', 'measured']) {
    for (let index = 0; index < 12; index++) {
      const derive = (name, length) => new Uint8Array(createHash('shake256', { outputLength: length })
        .update(`published-memory-v1/${parameter}/${group}/${index}/${name}`).digest());
      const seed = derive('seed', 32), message = derive('message', [0, 64, 1024, 4096][index % 4]);
      const context = derive('context', [0, 31, 255][index % 3]);
      const alg = api[`ml_dsa${parameter}`], keys = alg.keygen(seed);
      const signature = alg.sign(message, keys.secretKey, { context, extraEntropy: false });
      rows.push({ parameter, group, index, seed: hex(seed), message: hex(message), context: hex(context),
        publicKey: hex(keys.publicKey), secretKey: hex(keys.secretKey), signature: hex(signature) });
    }
  }
}
writeFileSync(process.argv[3], JSON.stringify({ schema: 'noble-memory-fixture-v1', rows }) + '\n', { flag: 'wx' });
