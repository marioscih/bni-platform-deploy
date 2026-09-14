import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

export async function loadSnapshot(path) {
  try { return JSON.parse(await readFile(path, "utf8")); }
  catch (error) { if (error.code === "ENOENT") return null; throw error; }
}

export function atomicJsonCommitter(path) {
  return async (snapshot) => {
    await mkdir(dirname(path), { recursive: true });
    const temporary = `${path}.next`;
    await writeFile(temporary, `${JSON.stringify(snapshot)}\n`, { mode: 0o600 });
    await rename(temporary, path);
  };
}
