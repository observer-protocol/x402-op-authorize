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
    out.push(`${name} -> ${v.resolved}  (package.json declares "${pkg.dependencies[name]}")`);
  }
  process.stdout.write(out.join("\n"));
' 2>/dev/null)"
if [ -n "${LINKED}" ]; then
  cat >&2 <<LINKED_EOF

  REFUSING TO PUBLISH A LINKED RUNTIME DEPENDENCY

  The lockfile resolves these runtime dependencies to local directories rather than to
  the registry:

$(echo "${LINKED}" | sed 's/^/      /')

  These are bundled into dist/ at build time. Publishing now ships code from a directory
  that is outside this repository, identified by no version, commit or checksum, and
  present only on machines that happen to have that checkout at that relative path.

  Nobody can reconstruct the artifact, and nobody can say what logic is inside it.
  The working tree being clean and pushed does not help: the linked directory is not
  part of this repository.

  Fix: relock the dependency to the registry, e.g.

      npm install <name>@<exact-version>     # then confirm the lockfile has no "link": true

LINKED_EOF
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
