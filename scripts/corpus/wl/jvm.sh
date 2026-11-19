#!/bin/bash
# OpenJDK 25: source-launched HttpServer (thread pool) + HttpClient, a hot loop for the JIT.
# programs: conda-openjdk
set -euo pipefail; shopt -s inherit_errexit
exec $PROGS/conda-openjdk/25.0.2/bin/java -Xmx256m -Xshare:auto $GUEST/Server.java
