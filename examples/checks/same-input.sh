# lint-allow: strict-line — sourced by same-output and same-tree, which set their own mode
# same_input REF RUN [FIELD...]: whether the reference run REF had the input the run RUN had,
# from their run.json files: the case's id, the work tree's source and place, --stdin, and the
# case line's own settings (which hold its --work and --stdin). FIELDs named (case-id, work,
# stdin, settings) are not compared.
# The program may differ (a reference implementation). Prints the first difference and
# returns 2 (an error, never a finding); returns 0 when they match. Sourced by same-output and
# same-tree; needs jq.
same_input() {
    _ref=$1 _run=$2
    shift 2
    _diff=$(jq -nr --slurpfile a "$_ref/run.json" --slurpfile b "$_run/run.json" --arg relax " $* " '
        def input: {
            "case-id": .config.case.id,
            work: [.config.work, .config["work-at"]],
            stdin: .config.stdin,
            settings: (.config.case.line // "" | if startswith("--") then .[:index(" -- ")] else "" end)
        };
        ($a[0] | input) as $x | ($b[0] | input) as $y
        | first($x | keys_unsorted[] | . as $k | select($relax | contains(" " + $k + " ") | not)
            | select($x[.] != $y[.])
            | "reference-mismatch: \(.) differs: the reference has \($x[.] | tojson), this run \($y[.] | tojson) (--relax \(.) to compare anyway)") // empty') || return 2
    [ -z "$_diff" ] && return 0
    echo "$_diff"
    return 2
}
