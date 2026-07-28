#!/bin/bash
# Refuse to publish from a working tree that is not committed.
#
# WHY THIS EXISTS
# ---------------
# Measured 2026-07-28 across this estate: of 23 published versions, 14 were
# published from a dirty tree. The recorded npm `gitHead` is the PRE-BUMP head,
# so the published artifact is `gitHead` plus an uncommitted edit and therefore
# corresponds to NO committed state.
#
# The consequence is not bookkeeping. Building the pinned commit and comparing
# against the published tarball showed the pin does not reproduce the shipped
# bytes for l402 0.3.2, wdk 0.3.2, mppx 0.2.0 and x402 0.1.0. Builds were
# confirmed deterministic, so those are pin failures rather than build noise:
# nobody can say which source produced those artifacts, including us.
#
# It is inconsistent per package, which is worse than uniform: policy-engine
# 0.2.0 and 0.3.3 are clean while 0.3.0 through 0.3.2 are not. No single
# reconstruction rule applies and nothing announces which kind you are looking at.
#
# This closes it at the source. Fail loudly, before the tarball is built.

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

  This is not hypothetical: 14 of this estate's 23 published versions are already
  in that state, and four of them provably cannot be reproduced from any commit.

  Commit the changes (or stash them) and publish again. If a version bump is the
  only pending change, prefer:

      npm version <patch|minor|major>     # bumps, commits and tags atomically
      npm publish

EOF
exit 1
