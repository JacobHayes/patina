#!/bin/bash
# Elixir 1.20 on Erlang/OTP 29: processes, gen_tcp server/clients, ETS, async_stream.
# programs: conda-elixir conda-erlang
set -euo pipefail; shopt -s inherit_errexit
export PATH=$PROGS/conda-erlang/29.1.2/bin:$PATH
# BEAM schedulers busy-wait by default (compute-stall under Patina): turn the busy wait off.
export ELIXIR_ERL_OPTIONS="+sbwt none +sbwtdcpu none +sbwtdio none"
exec $PROGS/conda-elixir/1.20.5/bin/elixir $GUEST/ex.exs
