import { parentPort } from 'node:worker_threads';
import { fingerprint } from './fingerprint.mjs';

// Long-lived: the dataset is parsed once per worker, not once per call.
parentPort.on('message', (input) => {
  try {
    parentPort.postMessage({ result: fingerprint(input) });
  } catch (err) {
    parentPort.postMessage({ error: err.message });
  }
});
