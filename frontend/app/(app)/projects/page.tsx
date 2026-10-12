"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState, type FormEvent } from "react";

import { Button, Card, ErrorMessage, Field } from "@/components/ui";
import { projectService } from "@/services/projects";
import type { Project } from "@/types/api";

export default function ProjectsPage() {
  const router = useRouter();
  const [projects, setProjects] = useState<Project[] | null>(null);
  const [listError, setListError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    projectService.list().then(setProjects, (e) => setListError(e.message));
  }, []);

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    setBusy(true);
    setError(null);
    try {
      const project = await projectService.create({
        name: String(form.get("name")),
        path: String(form.get("path")),
        description: String(form.get("description") ?? "").trim() || undefined,
      });
      router.push(`/projects/${project.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not create the project");
      setBusy(false);
    }
  }

  async function onUpload(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    const input = e.currentTarget.elements.namedItem("archive") as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) {
      setUploadError("Choose a .zip file to upload");
      return;
    }
    setBusy(true);
    setUploadError(null);
    try {
      const project = await projectService.upload(String(form.get("name")), file);
      router.push(`/projects/${project.id}`);
    } catch (err) {
      setUploadError(err instanceof Error ? err.message : "Could not upload the archive");
      setBusy(false);
    }
  }

  return (
    <div className="flex max-w-5xl flex-col gap-6">
      <header>
        <h1 className="text-2xl font-semibold">Projects</h1>
        <p className="mt-1 text-sm text-muted">
          Register a source directory once, confirm you are authorized to audit it, then run audits
          against it. Source code is only read, never executed.
        </p>
      </header>

      <Card title="Register a project">
        <form onSubmit={onSubmit} className="flex flex-col gap-4">
          <Field label="Name" name="name" required maxLength={120} placeholder="Shop API" />
          <Field
            label="Source directory (on the server)"
            name="path"
            required
            placeholder="/workspace/shop"
            hint="Must be under the server's SOURCE_ROOTS (docker compose mounts ./workspace at /workspace)."
          />
          <Field label="Description (optional)" name="description" maxLength={2000} />
          <ErrorMessage message={error} />
          <Button type="submit" disabled={busy} className="self-start">
            {busy ? "Registering…" : "Register project"}
          </Button>
        </form>
      </Card>

      <Card title="Or upload a zip of your code">
        <form onSubmit={onUpload} className="flex flex-col gap-4">
          <Field label="Project name" name="name" required maxLength={120} placeholder="Shop API" />
          <Field
            label="Zip archive"
            name="archive"
            type="file"
            accept=".zip,application/zip"
            hint="Unpacked into a private folder on the server, only read, and deleted when you delete the project. Symlinks and unsafe paths are rejected."
          />
          <ErrorMessage message={uploadError} />
          <Button type="submit" disabled={busy} className="self-start">
            {busy ? "Uploading…" : "Upload and create project"}
          </Button>
        </form>
      </Card>

      <Card title="Your projects">
        <ErrorMessage message={listError} />
        {!projects && !listError && <p className="text-sm text-muted">Loading…</p>}
        {projects && projects.length === 0 && (
          <p className="text-sm text-muted">No projects yet. Register one above.</p>
        )}
        {projects && projects.length > 0 && (
          <ul className="flex flex-col divide-y divide-border text-sm">
            {projects.map((p) => (
              <li key={p.id} className="flex flex-wrap items-center justify-between gap-2 py-3">
                <div>
                  <Link href={`/projects/${p.id}`} className="font-medium text-accent hover:underline">
                    {p.name}
                  </Link>
                  <p className="font-mono text-xs text-muted">{p.path}</p>
                </div>
                <span className={p.authorization_confirmed ? "text-success" : "text-warning"}>
                  {p.authorization_confirmed ? "Authorized" : "Not authorized"}
                </span>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
