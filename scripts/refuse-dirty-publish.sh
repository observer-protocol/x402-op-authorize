#!/bin/bash
# Refuse to publish unless the published artifact corresponds to a fetchable commit.
#
# WHAT THIS ENFORCES
# ------------------
# npm records the current HEAD as `gitHead` in the published package metadata. That
# pointer is the only machine-readable link from a published artifact back to the
# source that produced it. It is only meaningful if two things hold at publish time:
#
#   1. the working tree is CLEAN, so the artifact is built from that commit and not
#      from that commit plus uncommitted edits, and
#   2. the commit is PUSHED, so someone other than the publisher can actually fetch it.
#
# Neither is enforced by npm. This script enforces both, and fails before the tarball
# is built rather than after it is uploaded.
#
# Untracked files count as dirty on purpose: a file that is not committed cannot be
# reconstructed from the repository whether or not git is tracking it yet, and it may
# still be included in the tarball via the `files` list.
#
# Note for anyone bumping a version: prefer `npm version <patch|minor|major>`, which
# bumps, commits and tags atomically, over editing package.json by hand and leaving
# the change uncommitted at publish time.

set -u

# Untracked files are included on purpose. A file that is not committed cannot be
# reconstructed from the repository, whether or not git is tracking it yet, and it
# may well be in the tarball via `files`.
DIRT="$(git status --porcelain 2>/dev/null)"

# HEAD MUST ALSO BE PUSHED.
# A committed-but-unpushed HEAD passes the dirty check and still fails the purpose:
# npm records that commit as gitHead, and it exists only on one machine. A consumer,
# a colleague, or a future audit cannot fetch it, so the artifact is no more
# reconstructible than one built from uncommitted changes.
#
# This is the same defect as opdeploy shipping from local HEAD and production running
# code committed nowhere. Third substrate, same rule: what ships must correspond to a
# state others can obtain.
UP="$(git rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null || true)"
if [ -z "${UP}" ]; then
  echo "  REFUSING: branch has no upstream, so HEAD cannot be shown to exist anywhere but this machine." >&2
  exit 1
fi
AHEAD="$(git rev-list --count "${UP}..HEAD" 2>/dev/null || echo '?')"
if [ "${AHEAD}" != "0" ]; then
  cat >&2 <<UNPUSHED

  REFUSING TO PUBLISH FROM AN UNPUSHED COMMIT

  HEAD is $(git rev-parse --short HEAD), ${AHEAD} commit(s) ahead of ${UP}.

  npm will record this commit as gitHead. It exists only on this machine, so nobody
  can fetch the source of the artifact you are about to publish. That is the same
  failure as publishing from a dirty tree, one step later.

  Push first, then publish.

UNPUSHED
  exit 1
fi

# NO LINKED RUNTIME DEPENDENCY MAY BE BUNDLED.
# Measured 2026-07-28: three adapters declared a registry range for the shared core and
# their committed lockfile silently overrode it with `"link": true` pointing at a sibling
# working directory. The bundler inlines that code into dist/, so the published artifact
# carried logic from a directory that is outside the repository, identified by no version,
# commit or checksum, and present only on one machine.
#
# A clean, pushed tree does not catch this: the tree WAS clean and pushed. This is the
# check that would have.
LINKED="$(node -e '
  const fs=require("fs");
  let lock,pkg;
  try{lock=JSON.parse(fs.readFileSync("package-lock.json","utf8"));}catch(e){process.exit(0);}
  try{pkg=JSON.parse(fs.readFileSync("package.json","utf8"));}catch(e){process.exit(0);}
  // Runtime AND dev: esbuild --bundle inlines whatever it resolves, and does not care
  // how the dependency is classified. Measured 2026-07-28: ows-op-verify declares the
  // shared core as a devDependency, its lockfile links it to a sibling working
  // directory, and it bundles it into dist anyway. A runtime-only check skipped it, so
  // the guard written for exactly this failure could not see the one package it was
  // happening on. Classification is not the property that matters; bundling is.
  const runtime=new Set([...Object.keys(pkg.dependencies||{}),...Object.keys(pkg.devDependencies||{})]);
  const out=[];
  for(const[p,v]of Object.entries(lock.packages||{})){
    if(!v||!v.link)continue;
    const name=p.replace(/^.*node_modules\//,"");
    if(!p.startsWith("node_modules/"))continue;
    if(!runtime.has(name))continue;
    // Report the map the dependency was ACTUALLY found in. This read `pkg.dependencies`
    // unconditionally and printed "undefined" for anything declared in devDependencies,
    // which is most of what it catches. A guard whose message is demonstrably false about
    // what it found is a guard someone relaxes on the strength of its own inaccuracy.
    const map = (pkg.dependencies||{})[name] !== undefined ? "dependencies"
              : (pkg.devDependencies||{})[name] !== undefined ? "devDependencies" : "(not declared)";
    const declared = map === "(not declared)" ? "" : ` as "${(pkg[map]||{})[name]}"`;
    out.push(`${name} -> ${v.resolved}  (declared in ${map}${declared})`);
  }
  process.stdout.write(out.join("\n"));
' 2>/dev/null)"
if [ -n "${LINKED}" ]; then
  cat >&2 <<LINKED_EOF

  REFUSING TO PUBLISH: A DEPENDENCY RESOLVES OUTSIDE THE REGISTRY

  The lockfile resolves these dependencies to local directories rather than to the
  registry:

$(echo "${LINKED}" | sed 's/^/      /')

  THIS CHECKS RESOLUTION, NOT INCLUSION. It does not claim these reach dist/, and it
  does not need to: a published artifact must be reconstructible from published inputs,
  and a dependency resolved from a directory outside this repository is identified by no
  version, commit or checksum and exists only on machines that happen to have that
  checkout at that relative path. That is true whether or not the code is bundled.

  The rule has a real instance behind it rather than being prudence: this repository was
  found resolving its core to a .tgz in an ephemeral scratch directory from an earlier
  tooling session, pinned to a superseded version, on a path that no longer existed.
  It had been building against a core nobody could reconstruct or identify, us included.

  The working tree being clean and pushed does not help: the linked directory is not
  part of this repository.

  Fix: relock the dependency to the registry, e.g.

      npm install <name>@<exact-version>     # then confirm the lockfile has no "link": true

LINKED_EOF
  exit 1
fi

# ─── The core resolved in the lockfile must satisfy the floor package.json declares ───
#
# THE QUIET SHAPE. The other three failures this guard catches are visible on sight: a
# "link": true, a file: path, a .tgz in a scratch directory. This one is a perfectly
# well-formed registry resolution at a STALE VERSION, and it passes every other check here.
#
# It nearly shipped: one package in the 0.4.0 fanout carried a committed lockfile pinning the
# core to 0.3.3 while declaring ">=0.4.0 <1.0.0". Build succeeded, suite passed, guard was
# silent, and publishing would have shipped a superseded core with nothing objecting.
#
# The floor is derivable from what is already here, so this needs no new input and cannot
# drift from the release: the range's lower bound is the version being fanned out.
STALE_CORE="$(node -e '
  const fs=require("fs");
  let pkg,lock;
  try{pkg=JSON.parse(fs.readFileSync("package.json","utf8"));lock=JSON.parse(fs.readFileSync("package-lock.json","utf8"));}catch(e){process.exit(0)}
  const NAME="@observer-protocol/policy-engine";
  const decl=(pkg.dependencies||{})[NAME]||(pkg.devDependencies||{})[NAME];
  if(!decl)process.exit(0);
  const m=/>=\s*([0-9]+)\.([0-9]+)\.([0-9]+)/.exec(decl);
  if(!m)process.exit(0);                      // no floor declared, nothing to compare
  const entry=(lock.packages||{})["node_modules/"+NAME];
  if(!entry||!entry.version)process.exit(0);   // absence is the linked-dependency check above
  const got=entry.version.split(".").map(Number);
  const floor=[+m[1],+m[2],+m[3]];
  const lower=got[0]<floor[0]||(got[0]===floor[0]&&(got[1]<floor[1]||(got[1]===floor[1]&&got[2]<floor[2])));
  if(lower)process.stdout.write(entry.version+" | "+decl);
' 2>/dev/null)"
if [ -n "${STALE_CORE}" ]; then
  RESOLVED="${STALE_CORE%% | *}"; DECLARED="${STALE_CORE##* | }"
  cat >&2 <<STALE_EOF

  REFUSING TO PUBLISH AGAINST A STALE CORE

  package.json declares  @observer-protocol/policy-engine  ${DECLARED}
  the lockfile resolves            ${RESOLVED}

  The resolution is well-formed and from the registry, so every other check here passes.
  The lockfile is simply older than the release: the build, the suite and this guard would
  all be green while the artifact carried a superseded core.

  This is what the fanout exists to prevent. Every adapter bundles the core into dist/ at
  build time, so publishing now ships ${RESOLVED} to consumers who will believe they have
  ${DECLARED}.

  Fix: regenerate the lockfile against the registry.

      rm -rf node_modules package-lock.json && npm install
      npm run build && npm test

STALE_EOF
  exit 1
fi

if [ -z "${DIRT}" ]; then
  echo "publish guard: working tree clean at $(git rev-parse --short HEAD). gitHead will identify the source."
  exit 0
fi

cat >&2 <<EOF

  REFUSING TO PUBLISH FROM A DIRTY TREE

  HEAD is $(git rev-parse --short HEAD), but the working tree has uncommitted changes:

$(echo "${DIRT}" | sed 's/^/      /')

  npm records gitHead as the CURRENT HEAD. Publishing now ships bytes built from
  HEAD plus the changes above, so the published artifact will correspond to no
  commit and nobody will be able to establish what produced it later.

  Commit the changes (or stash them) and publish again. If a version bump is the
  only pending change, prefer:

      npm version <patch|minor|major>     # bumps, commits and tags atomically
      npm publish

EOF
exit 1
