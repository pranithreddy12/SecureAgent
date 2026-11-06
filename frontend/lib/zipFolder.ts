import JSZip from "jszip";

// Directories that are never useful to scan and often blow past the upload limit.
const SKIP_SEGMENTS = new Set([
  "node_modules",
  ".git",
  ".next",
  ".venv",
  "venv",
  "dist",
  "build",
  "__pycache__",
  ".cache",
]);

// Databases and other big binaries are data, not source: they only push the zip past the upload limit.
const SKIP_EXTENSIONS = /\.(db|sqlite|sqlite3)$/i;
const MAX_FILE_BYTES = 5 * 1024 * 1024;

function isSkipped(relPath: string, size = 0): boolean {
  return (
    relPath.split("/").some((seg) => SKIP_SEGMENTS.has(seg)) ||
    SKIP_EXTENSIONS.test(relPath) ||
    size > MAX_FILE_BYTES
  );
}

/** A file with its path relative to (and including) the picked folder, e.g. `myapp/src/a.py`. */
export interface PickedFile {
  path: string;
  file: File;
}

export function fromFileList(files: FileList): PickedFile[] {
  return Array.from(files).map((f) => ({ path: f.webkitRelativePath || f.name, file: f }));
}

/** The project name a folder pick suggests: the top-level folder name. */
export function suggestedProjectName(files: PickedFile[]): string {
  return (files[0]?.path ?? "project").split("/")[0];
}

// The File System Access API (Chromium and Electron). Typed by hand: lib.dom does not ship it.
type Handle =
  | { kind: "file"; name: string; getFile(): Promise<File> }
  | { kind: "directory"; name: string; values(): AsyncIterable<Handle> };
type DirHandle = Extract<Handle, { kind: "directory" }>;

export function canPickLazily(): boolean {
  return typeof window !== "undefined" && "showDirectoryPicker" in window;
}

async function walk(dir: DirHandle, prefix: string, out: PickedFile[], skipped: { n: number }) {
  for await (const h of dir.values()) {
    if (h.kind === "directory") {
      if (SKIP_SEGMENTS.has(h.name)) skipped.n++; // never entered: no listing of node_modules
      else await walk(h, `${prefix}${h.name}/`, out, skipped);
    } else if (SKIP_EXTENSIONS.test(h.name)) {
      skipped.n++;
    } else {
      const file = await h.getFile();
      if (file.size > MAX_FILE_BYTES) skipped.n++;
      else out.push({ path: prefix + h.name, file });
    }
  }
}

/**
 * Let the user pick a folder and read only what is worth scanning. Unlike `<input webkitdirectory>`,
 * which makes the browser list every file first (minutes for a folder holding `node_modules`), this
 * walks the folder itself and never enters the skipped directories. `null` = the user cancelled.
 */
export async function pickFolderLazily(): Promise<{ files: PickedFile[]; skipped: number } | null> {
  const pick = (window as unknown as { showDirectoryPicker(): Promise<DirHandle> })
    .showDirectoryPicker;
  let root: DirHandle;
  try {
    root = await pick.call(window);
  } catch (e) {
    if (e instanceof DOMException && e.name === "AbortError") return null;
    throw e;
  }
  const files: PickedFile[] = [];
  const skipped = { n: 0 };
  await walk(root, `${root.name}/`, files, skipped);
  return { files, skipped: skipped.n };
}

/**
 * Zip a folder selection client-side, so it can be sent to the existing `/api/projects/upload`
 * endpoint (ADR-019) without the user zipping it by hand. Build output and dependency directories
 * are skipped; the server re-checks size and safety on the way in (zip-slip, bombs, symlinks), so
 * this is a convenience filter, not the security check.
 */
export async function zipFolder(
  files: PickedFile[],
): Promise<{ file: File; fileCount: number; skipped: number }> {
  const zip = new JSZip();
  let fileCount = 0;
  let skipped = 0;
  for (const { path, file } of files) {
    if (isSkipped(path, file.size)) {
      skipped++;
      continue;
    }
    zip.file(path, file);
    fileCount++;
  }
  const blob = await zip.generateAsync({
    type: "blob",
    compression: "DEFLATE",
    compressionOptions: { level: 6 },
  });
  return { file: new File([blob], "project.zip", { type: "application/zip" }), fileCount, skipped };
}
