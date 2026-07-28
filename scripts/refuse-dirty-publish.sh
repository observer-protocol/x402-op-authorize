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
