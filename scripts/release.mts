#!/usr/bin/env node
/**
 * Bumps the crate version, tags the release commit, and pushes both so the
 * `Build and maybe release` workflow publishes the GitHub release.
 * @module
 */

import { readFile, writeFile } from "node:fs/promises";
import { $ } from "zx";

/** Semver component incremented by a release. */
type ReleaseBump = "patch" | "minor" | "major";

/** Plain `MAJOR.MINOR.PATCH` release version. */
interface Version {
    major: number;
    minor: number;
    patch: number;
}

/** Manifest whose package version is bumped for every release. */
const cargoTomlPath = "Cargo.toml";

/** Print an error and stop the release without touching anything further. */
function fail(message: string): never {
    console.error(`Error: ${message}`);
    process.exit(1);
}

/** Fail early so a dirty tree cannot leak into the version bump commit. */
async function requireCleanWorkingTree(): Promise<void> {
    const statusOutput = await $`git status --porcelain`.nothrow();
    if (statusOutput.stdout.trim() !== "") {
        fail(
            "There are uncommitted changes or untracked files. Please commit or stash them before releasing.",
        );
    }
}

/** Releases must come from main so tags always point at the integration branch. */
async function requireMainBranch(): Promise<void> {
    const currentBranch = (await $`git rev-parse --abbrev-ref HEAD`).stdout.trim();
    if (currentBranch !== "main") {
        fail(`You must be on the 'main' branch to release. Current branch: '${currentBranch}'.`);
    }
}

/** A rejected push is the remote saying this tip cannot become the release. */
async function requireSyncedWithOriginMain(): Promise<void> {
    const pushResult = await $`git push origin main`.nothrow();
    if (pushResult.exitCode !== 0) {
        fail(
            "Local main is not in sync with origin/main. Pull until `git push origin main` succeeds.",
        );
    }

    // Treat origin as authoritative so stale local tags cannot affect the next version.
    await $`git fetch origin --tags --force --prune --prune-tags`;
}

/** Skills cannot answer prompts, so the bump type is a required CLI argument. */
function parseReleaseBump(argument: string | undefined): ReleaseBump {
    if (argument === "patch" || argument === "minor" || argument === "major") {
        return argument;
    }

    console.error("Usage: node scripts/release.mts <patch|minor|major>");
    process.exit(1);
}

/** Parse a plain `MAJOR.MINOR.PATCH` version, rejecting prerelease and build suffixes. */
function parseVersion(text: string): Version | undefined {
    const match = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.exec(text);
    if (match === null) {
        return undefined;
    }

    return {
        major: Number(match[1]),
        minor: Number(match[2]),
        patch: Number(match[3]),
    };
}

/** Increment one semver component and reset the less significant ones. */
function bumpVersion(version: Version, bump: ReleaseBump): string {
    switch (bump) {
        case "major":
            return `${version.major + 1}.0.0`;
        case "minor":
            return `${version.major}.${version.minor + 1}.0`;
        case "patch":
            return `${version.major}.${version.minor}.${version.patch + 1}`;
    }
}

/** Read the package version from the Cargo manifest text. */
function cargoPackageVersion(cargoToml: string): string {
    const match = /^version = "(.*)"$/m.exec(cargoToml);
    if (match?.[1] === undefined) {
        fail(`Could not find the package version in ${cargoTomlPath}.`);
    }

    return match[1];
}

/**
 * Pick the version the bump starts from: the latest published tag, or the
 * Cargo manifest version before the first release has been tagged.
 */
async function resolveCurrentVersion(cargoToml: string): Promise<string> {
    const tagOutput = await $`git tag -l 'v*' | sort -V | tail -n 1`;
    const latestTag = tagOutput.stdout.trim();
    if (latestTag === "") {
        const manifestVersion = cargoPackageVersion(cargoToml);
        console.log(
            `No release tags found; starting from ${cargoTomlPath} version ${manifestVersion}`,
        );
        return manifestVersion;
    }

    console.log(`Latest release tag: ${latestTag}`);
    return latestTag.replace(/^v/, "");
}

/** Increment the current version so the next release cannot collide with an existing one. */
function resolveNextVersion(currentVersion: string, bump: ReleaseBump): string {
    const version = parseVersion(currentVersion);
    if (version === undefined) {
        fail(`Invalid current version ${currentVersion}; expected MAJOR.MINOR.PATCH.`);
    }

    return bumpVersion(version, bump);
}

/** Refuse to rewrite a published tag; non-interactive releases must never be destructive. */
async function requireUnusedTag(newTag: string): Promise<void> {
    const localTagOutput = await $`git tag -l ${newTag}`.nothrow();
    const remoteTagOutput = await $`git ls-remote --tags origin ${newTag}`.nothrow();
    if (
        localTagOutput.stdout.trim() === newTag ||
        remoteTagOutput.stdout.trim().includes(`refs/tags/${newTag}`)
    ) {
        fail(`Tag ${newTag} already exists. Choose a newer bump or delete it manually.`);
    }
}

/** Write the new version into Cargo.toml and Cargo.lock and commit them. */
async function commitVersionBump(cargoToml: string, newVersion: string): Promise<void> {
    const updatedCargoToml = cargoToml.replace(/^version = ".*"$/m, `version = "${newVersion}"`);
    await writeFile(cargoTomlPath, updatedCargoToml);

    // Only the workspace entry changes, so no build (and no UI bundle) is needed.
    console.log("Updating Cargo.lock...");
    await $`cargo update --workspace --offline`;
    await $`git add ${cargoTomlPath} Cargo.lock`;

    const stagedOutput = await $`git diff --cached --name-only`.nothrow();
    if (stagedOutput.stdout.trim() !== "") {
        await $`git commit -m ${`Bump version to ${newVersion}`}`;
    } else {
        console.log("No version changes to commit, skipping commit.");
    }
}

const bump = parseReleaseBump(process.argv[2]);
await requireCleanWorkingTree();
await requireMainBranch();
await requireSyncedWithOriginMain();

const cargoToml = await readFile(cargoTomlPath, "utf-8");
const currentVersion = await resolveCurrentVersion(cargoToml);
const newVersion = resolveNextVersion(currentVersion, bump);
const newTag = `v${newVersion}`;
console.log(`Releasing ${newTag} (${bump})`);
await requireUnusedTag(newTag);

await commitVersionBump(cargoToml, newVersion);
await $`git tag -a ${newTag} -m ${`Release ${newTag}`}`;
await $`git push origin HEAD`;
await $`git push origin ${newTag}`;
console.log(`Released ${newTag}`);
