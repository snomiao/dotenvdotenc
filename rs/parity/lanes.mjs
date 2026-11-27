#!/usr/bin/env node
// Splits a cases file into lanes, for parity runs side by side (the runner
// runs one case at a time, and a case of dede's starts bun, git and a shell
// several times):
//
//   node rs/parity/lanes.mjs <cases.json> <lanes> <directory>
//
// writes <directory>/lane-0.json … lane-<lanes - 1>.json, each with the
// file's own settings and every <lanes>-th case, so that each case is in
// exactly one lane and cases of one kind are spread over all of them. The
// runner takes <REPO> from the directory it is started in, not from where
// the cases file is, so a lane runs its cases as rs/parity.json would.

import fs from "node:fs";
import path from "node:path";

const [file, count, dir] = process.argv.slice(2);
const lanes = Number(count);
if (!file || !dir || !Number.isInteger(lanes) || lanes < 1) {
  console.error("usage: lanes.mjs <cases.json> <lanes> <directory>");
  process.exit(2);
}
const spec = JSON.parse(fs.readFileSync(file, "utf8"));
fs.mkdirSync(dir, { recursive: true });
for (let lane = 0; lane < lanes; lane++) {
  const cases = spec.cases.filter((_, index) => index % lanes === lane);
  fs.writeFileSync(path.join(dir, `lane-${lane}.json`), JSON.stringify({ ...spec, cases }));
}
console.log(`${spec.cases.length} cases in ${lanes} lane(s)`);
