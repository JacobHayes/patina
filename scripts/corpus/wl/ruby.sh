#!/bin/bash
# Ruby 4: threaded TCP server and clients, fork/pipe/wait, Queue workers, files.
# programs: conda-ruby
set -euo pipefail; shopt -s inherit_errexit
exec $PROGS/conda-ruby/4.0.9/bin/ruby $GUEST/rb.rb
