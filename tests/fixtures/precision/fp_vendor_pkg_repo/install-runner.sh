#!/bin/bash
# Also from nvidia/aistore. GitLab publishes this exact installer command in its
# own documentation. The reputable-host list had the toolchain installers but not
# the vendor package repositories.
set -e
curl -L https://packages.gitlab.com/install/repositories/runner/gitlab-runner/script.deb.sh | bash
curl -fsSL https://dl.yarnpkg.com/debian/pubkey.gpg | apt-key add -
