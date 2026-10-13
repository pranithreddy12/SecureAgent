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

function isSkipped(relPath: string): boolean {
  return relPath.split("/").some((seg) => SKIP_SEGMENTS.has(seg));
}

/** The project name a `webkitdirectory` file list suggests: the top-level folder name. */
export function suggestedProjectName(files: FileList): string {
  const first = files[0]?.webkitRelativePath || files[0]?.name || "project";
  return first.split("/")[0];
}

/**
 * Zip a browser folder selection (an `<input webkitdirectory>` FileList) client-side, so it can be
 * sent to the existing `/api/projects/upload` endpoint (ADR-019) without the user zipping it by
 * hand. Build output and dependency directories are skipped; the server re-checks size and safety
 * on the way in (zip-slip, bombs, symlinks), so this is a convenience filter, not the security check.
 */
export async function zipFolder(
  files: FileList,
): Promise<{ file: File; fileCount: number; skipped: number }> {
  const zip = new JSZip();
  let fileCount = 0;
  let skipped = 0;
  for (const f of Array.from(files)) {
    const rel = f.webkitRelativePath || f.name;
    if (isSkipped(rel)) {
      skipped++;
      continue;
    }
    zip.file(rel, f);
    fileCount++;
  }
  const blob = await zip.generateAsync({
    type: "blob",
    compression: "DEFLATE",
    compressionOptions: { level: 6 },
  });
  return { file: new File([blob], "project.zip", { type: "application/zip" }), fileCount, skipped };
}
