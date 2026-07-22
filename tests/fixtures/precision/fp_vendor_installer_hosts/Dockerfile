# From photoprism/photoprism, cyotee/crane and adityavanjre/project-k, all of which
# confirmed AUTO on the 2026-07-21 hunt. Each line is a vendor's own documented
# installer. The curl-pipe-shell rule used to carry a short inline host allowlist
# that had drifted from the real one, so these hosts were unknown to it.
FROM ubuntu:24.04

RUN curl -fsSL https://claude.ai/install.sh | bash
RUN curl -sSfL https://release.anza.xyz/stable/install | bash
RUN curl -fsSL https://ollama.com/install.sh | sh
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash -

CMD ["/usr/bin/app"]
