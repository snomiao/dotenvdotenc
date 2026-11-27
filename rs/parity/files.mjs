#!/usr/bin/env node
// What a parity case's `after` line asks about files, the same way on Linux,
// macOS and Windows (in Git Bash). GNU `stat -c` and `sha256sum` are not on
// a Mac, and BSD `stat -f` is not on Linux; node is on all three.
//
//   node rs/parity/files.mjs stat <format> [file…]
//       one line per file, as GNU `stat -c <format>` prints it (the link
//       itself for a symbolic link): %a the permission bits in octal (644,
//       1777), %F the kind of file (regular file, regular empty file,
//       directory, symbolic link, fifo, socket, character special file, block
//       special file), %n the name as given, %u the owner's uid, %% a
//       percent sign. Without files, the names are read from standard input,
//       one per line (`ls -A | node rs/parity/files.mjs stat '%a %F %n'`).
//       A file that is not there is said so on standard error, exit code 1.
//   node rs/parity/files.mjs sha256 [file…]
//       the SHA-256 of each file, or of standard input, as sha256sum prints
//       it.
//
// On Windows the modes are what node makes of a file there (666, or 444
// for a read-only one), the same for both implementations.

import { createHash } from "node:crypto";
import fs from "node:fs";

const [what, ...args] = process.argv.slice(2);

const KINDS = [
  ["isFile", "regular file"],
  ["isDirectory", "directory"],
  ["isSymbolicLink", "symbolic link"],
  ["isFIFO", "fifo"],
  ["isSocket", "socket"],
  ["isCharacterDevice", "character special file"],
  ["isBlockDevice", "block special file"],
];
const kind = (st) => {
  const [, name] = KINDS.find(([test]) => st[test]()) || [, "weird file"];
  return name === "regular file" && st.size === 0 ? "regular empty file" : name;
};
const names = (given) => (given.length ? given : fs.readFileSync(0, "utf8").split("\n").filter((line) => line !== ""));

let failed = false;
if (what === "stat" && args.length) {
  const [format, ...files] = args;
  for (const file of names(files)) {
    let st;
    try {
      st = fs.lstatSync(file);
    } catch (e) {
      console.error(`files.mjs: cannot stat '${file}': ${e.code}`);
      failed = true;
      continue;
    }
    const fields = { a: (st.mode & 0o7777).toString(8), F: kind(st), n: file, u: String(st.uid), "%": "%" };
    console.log(format.replace(/%(.)/g, (all, letter) => fields[letter] ?? all));
  }
} else if (what === "sha256") {
  const hash = (data) => createHash("sha256").update(data).digest("hex");
  if (!args.length) console.log(`${hash(fs.readFileSync(0))}  -`);
  for (const file of args) {
    try {
      console.log(`${hash(fs.readFileSync(file))}  ${file}`);
    } catch (e) {
      console.error(`files.mjs: ${file}: ${e.code}`);
      failed = true;
    }
  }
} else {
  console.error("usage: files.mjs stat <format> [file…] | files.mjs sha256 [file…]");
  process.exit(2);
}
process.exit(failed ? 1 : 0);
