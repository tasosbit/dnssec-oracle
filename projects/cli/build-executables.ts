#!/usr/bin/env bun

// @ts-ignore - Bun types not available in TypeScript
import { $ } from "bun";
import { existsSync, mkdirSync } from "fs";
import { join } from "path";

async function buildStandalone() {
  const distDir = "dist";
  const exeDir = "dist-exe";
  const standaloneDir = join(exeDir, "standalone");

  // Ensure directories exist
  if (!existsSync(standaloneDir)) {
    mkdirSync(standaloneDir, { recursive: true });
  }

  console.log("Building TypeScript to JavaScript...");
  await $`pnpm run build:ts`;

  console.log("Creating standalone executables for multiple platforms...");
  
  const targets = [
    { platform: "linux", arch: "x64", output: "dnssec-oracle-linux-x64" },
    { platform: "linux", arch: "arm64", output: "dnssec-oracle-linux-arm64" },
    { platform: "darwin", arch: "x64", output: "dnssec-oracle-macos-x64" },
    { platform: "darwin", arch: "arm64", output: "dnssec-oracle-macos-arm64" },
    { platform: "windows", arch: "x64", output: "dnssec-oracle-windows-x64.exe" }
  ];

  // optional filter, e.g. `bun run build-executables.ts linux-x64`
  const only = process.argv[2];
  const selected = only ? targets.filter((t) => `${t.platform}-${t.arch}` === only) : targets;
  if (selected.length === 0) throw new Error(`Unknown target ${only}: use <linux|darwin|windows>-<x64|arm64>`);

  for (const target of selected) {
    try {
      console.log(`Building for ${target.platform}-${target.arch}...`);
      const bunTarget = `bun-${target.platform}-${target.arch}`;
      const outputPath = join(standaloneDir, target.output);
      
      await $`bun build ${distDir}/index.js --compile --target=${bunTarget} --outfile=${outputPath}`;
      
      if (target.platform !== "windows") {
        await $`chmod +x ${outputPath}`;
      }
      
      console.log(`✅ ${target.output} created successfully`);
    } catch (error) {
      console.warn(`⚠️  Failed to build for ${target.platform}-${target.arch}: ${error}`);
    }
  }

  console.log("📦 Standalone executables created in:", standaloneDir);
  
  // Show file sizes
  try {
    const stats = await $`ls -lh ${standaloneDir}/`.text();
    console.log("📊 File sizes:");
    console.log(stats);
  } catch (error) {
    console.log("Could not display file sizes");
  }
}

buildStandalone().catch((error) => {
  console.error("❌ Build failed:", error);
  process.exit(1);
});

