import { afterEach, describe, expect, it } from "vitest";

import { canPickLazily, pickFolderLazily } from "./zipFolder";

interface FakeFile {
  kind: "file";
  name: string;
  getFile(): Promise<File>;
}
interface FakeDir {
  kind: "directory";
  name: string;
  values(): AsyncIterable<Entry>;
}
type Entry = FakeFile | FakeDir;

const file = (name: string, size = 10): FakeFile => ({
  kind: "file",
  name,
  getFile: async () => Object.defineProperty(new File(["x"], name), "size", { value: size }),
});
const dir = (name: string, children: () => Entry[]): FakeDir => ({
  kind: "directory",
  name,
  values: async function* () {
    for (const c of children()) yield c;
  },
});

afterEach(() => {
  delete (window as unknown as Record<string, unknown>).showDirectoryPicker;
});

describe("pickFolderLazily", () => {
  it("walks the folder, never entering skipped directories, and drops databases and big files", async () => {
    const root = dir("app", () => [
      file("main.py"),
      dir("src", () => [file("a.py")]),
      dir("node_modules", () => {
        throw new Error("node_modules must not be listed");
      }),
      file("shop.db"),
      file("huge.bin", 6 * 1024 * 1024),
    ]);
    (window as unknown as Record<string, unknown>).showDirectoryPicker = async () => root;
    expect(canPickLazily()).toBe(true);
    const picked = await pickFolderLazily();
    expect(picked?.files.map((f) => f.path)).toEqual(["app/main.py", "app/src/a.py"]);
    expect(picked?.skipped).toBe(3);
  });

  it("returns null when the user cancels", async () => {
    (window as unknown as Record<string, unknown>).showDirectoryPicker = async () => {
      throw new DOMException("cancelled", "AbortError");
    };
    expect(await pickFolderLazily()).toBeNull();
  });
});
