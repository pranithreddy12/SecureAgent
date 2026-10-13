"use client";

import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";

import { AiConsent } from "@/components/AiConsent";
import { Button, Card, ErrorMessage, Field } from "@/components/ui";
import { suggestedProjectName, zipFolder } from "@/lib/zipFolder";
import { projectService } from "@/services/projects";
import type { Project, ProjectDetail } from "@/types/api";

type Source = "folder" | "existing";

/** One place to pick code, confirm authorization and launch an audit (ADR-011/019 wired into one
 * page instead of three). The run itself is visualised on the existing audit page, which already
 * shows every stage and every finding as it happens -- this page only gets a project to that point. */
export default function RunPage() {
  const router = useRouter();
  const fileInput = useRef<HTMLInputElement>(null);

  const [source, setSource] = useState<Source>("folder");
  const [projects, setProjects] = useState<Project[]>([]);
  const [projectsError, setProjectsError] = useState<string | null>(null);

  const [folderFiles, setFolderFiles] = useState<FileList | null>(null);
  const [folderSummary, setFolderSummary] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [existingId, setExistingId] = useState("");

  const [resolved, setResolved] = useState<ProjectDetail | null>(null); // set once a project is ready to run
  const [confirmed, setConfirmed] = useState(false);
  const [exclude, setExclude] = useState("");
  const [aiReview, setAiReview] = useState(false);

  const [phase, setPhase] = useState<"idle" | "resolving" | "starting">("idle");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    projectService.list().then(setProjects, (e) => setProjectsError(e.message));
  }, []);

  function onFolderPicked(files: FileList | null) {
    setFolderFiles(files);
    setResolved(null);
    setConfirmed(false);
    if (files && files.length > 0) {
      setName(suggestedProjectName(files));
      const bytes = Array.from(files).reduce((sum, f) => sum + f.size, 0);
      setFolderSummary(`${files.length} files, ${(bytes / (1024 * 1024)).toFixed(1)} MB`);
    } else {
      setFolderSummary(null);
    }
  }

  async function onExistingPicked(id: string) {
    setExistingId(id);
    setResolved(null);
    setConfirmed(false);
    setError(null);
    if (!id) return;
    setPhase("resolving");
    try {
      setResolved(await projectService.get(id));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not load that project");
    } finally {
      setPhase("idle");
    }
  }

  /** Zip + upload (folder mode) or just load (existing mode), landing on the authorize-and-run step. */
  async function prepare() {
    setError(null);
    setPhase("resolving");
    try {
      let project: Project;
      if (source === "folder") {
        if (!folderFiles || folderFiles.length === 0) throw new Error("Choose a folder first");
        if (!name.trim()) throw new Error("Give the project a name");
        const { file, fileCount } = await zipFolder(folderFiles);
        if (fileCount === 0) throw new Error("Every file in that folder was filtered out");
        project = await projectService.upload(name.trim(), file);
      } else {
        if (!existingId) throw new Error("Choose a project first");
        project = projects.find((p) => p.id === existingId)!;
      }
      setResolved(await projectService.get(project.id));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not prepare the project");
    } finally {
      setPhase("idle");
    }
  }

  async function startRun() {
    if (!resolved) return;
    setError(null);
    setPhase("starting");
    try {
      if (!resolved.authorization_confirmed) {
        await projectService.authorize(resolved.id);
      }
      const excludeList = exclude
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      const audit = await projectService.startAudit(resolved.id, excludeList, aiReview);
      router.push(`/audits/${audit.id}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not start the audit");
      setPhase("idle");
    }
  }

  const unauthorized = resolved && !resolved.authorization_confirmed;
  const canRun = resolved && (!unauthorized || confirmed) && phase !== "starting";

  return (
    <div className="flex max-w-3xl flex-col gap-6">
      <header>
        <h1 className="text-2xl font-semibold">Run an audit</h1>
        <p className="mt-1 text-sm text-muted">
          Point the scanner at some code, choose how it should analyse it, and watch every stage run.
        </p>
      </header>

      <Card title="1 · Source">
        <div className="mb-4 flex gap-2 text-xs">
          {([
            ["folder", "A folder on this computer"],
            ["existing", "A project you already registered"],
          ] as const).map(([key, label]) => (
            <button
              key={key}
              type="button"
              onClick={() => {
                setSource(key);
                setResolved(null);
                setConfirmed(false);
                setError(null);
              }}
              className={`rounded-lg border px-3 py-2 ${
                source === key ? "border-accent text-accent" : "border-border text-muted"
              }`}
            >
              {label}
            </button>
          ))}
        </div>

        {source === "folder" ? (
          <div className="flex flex-col gap-4">
            <div className="flex flex-col gap-1.5 text-sm">
              <span className="font-medium">Folder</span>
              <div className="flex items-center gap-3">
                <Button type="button" onClick={() => fileInput.current?.click()}>
                  Choose folder…
                </Button>
                {folderSummary && <span className="text-xs text-muted">{folderSummary}</span>}
              </div>
              <input
                ref={fileInput}
                type="file"
                className="hidden"
                // Non-standard but universally supported attributes for a directory picker.
                {...({ webkitdirectory: "", directory: "" } as Record<string, string>)}
                onChange={(e) => onFolderPicked(e.target.files)}
              />
              <span className="text-xs text-muted">
                Zipped in your browser and uploaded -- nothing is sent until you confirm below.
                node_modules, .git, build and venv directories are skipped automatically.
              </span>
            </div>
            <Field
              label="Project name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              maxLength={120}
              required
            />
          </div>
        ) : (
          <div className="flex flex-col gap-2 text-sm">
            <ErrorMessage message={projectsError} />
            {projects.length === 0 && !projectsError && (
              <p className="text-muted">
                No projects registered yet. Switch to “A folder on this computer”, or register one by
                server path on the Projects page.
              </p>
            )}
            {projects.length > 0 && (
              <select
                value={existingId}
                onChange={(e) => onExistingPicked(e.target.value)}
                className="h-10 rounded-lg border border-border bg-background px-3"
              >
                <option value="">Choose a project…</option>
                {projects.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name} ({p.path})
                  </option>
                ))}
              </select>
            )}
          </div>
        )}

        {!resolved && (
          <Button
            type="button"
            className="mt-4"
            disabled={phase === "resolving" || (source === "existing" ? !existingId : false)}
            onClick={prepare}
          >
            {phase === "resolving" ? "Preparing…" : "Continue"}
          </Button>
        )}
      </Card>

      {resolved && (
        <Card title="2 · How to analyse it">
          <div className="flex flex-col gap-3">
            <div className="flex items-start gap-2 rounded-lg border border-accent/40 bg-accent/5 p-3 text-sm">
              <span aria-hidden>✓</span>
              <span>
                <span className="font-medium">Static analysis</span>
                <span className="mt-1 block text-xs text-muted">
                  The deterministic source scanner -- taint tracking, secret detection, misconfiguration
                  and access-control rules. Always runs; nothing here is executed.
                </span>
              </span>
            </div>
            <AiConsent checked={aiReview} onChange={setAiReview} />
            <div className="flex items-start gap-2 rounded-lg border border-border p-3 text-sm text-muted/60">
              <span aria-hidden>○</span>
              <span className="flex-1">
                <span className="font-medium">Agent (MCP-driven)</span>
                <span className="mt-1 block text-xs">
                  An LLM agent that drives the scanner itself through its MCP tools, deciding what to
                  look at next. Not available yet.
                </span>
              </span>
              <span className="rounded border border-border px-1.5 text-[10px] uppercase">soon</span>
            </div>
            <Field
              label="Exclude patterns (optional)"
              value={exclude}
              onChange={(e) => setExclude(e.target.value)}
              placeholder="tests/*, *.min.js"
              hint="Comma-separated globs of files to skip."
            />
          </div>
        </Card>
      )}

      {resolved && (
        <Card title="3 · Authorization and run">
          {unauthorized ? (
            <label className="flex items-start gap-2 text-sm">
              <input
                type="checkbox"
                className="mt-1"
                checked={confirmed}
                onChange={(e) => setConfirmed(e.target.checked)}
              />
              <span>{resolved.authorization_statement}</span>
            </label>
          ) : (
            <p className="text-sm text-success">Authorized.</p>
          )}
          <ErrorMessage message={error} />
          <Button type="button" className="mt-4" disabled={!canRun} onClick={startRun}>
            {phase === "starting" ? "Starting…" : "Run security audit"}
          </Button>
        </Card>
      )}

      {!resolved && error && <ErrorMessage message={error} />}
    </div>
  );
}
