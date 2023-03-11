globalThis.require = require;
globalThis.fs = require("fs");
globalThis.TextEncoder = require("util").TextEncoder;
globalThis.TextDecoder = require("util").TextDecoder;

globalThis.performance = {
	now() {
		const [sec, nsec] = process.hrtime();
		return sec * 1000 + nsec / 1000000;
	},
};

const crypto = require("crypto");
globalThis.crypto = {
	getRandomValues(b) {
		crypto.randomFillSync(b);
	},
};

require('./wasm_exec')


const go = new Go(); // Defined in wasm_exec.js
const fs = require('fs')

const wasmBytes = fs.readFileSync('./json.wasm');

const foo  = async () => {
  const wasm = await WebAssembly.instantiate(wasmBytes, go.importObject)

  go.run(wasm.instance)
}

foo()
