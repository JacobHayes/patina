# Shared JSON field reader for the check scripts (sourced, not run); needs jq.
# field FILE PATH: the value at PATH, dot-separated (a numeric component indexes a list).
# A missing key, an index out of range or a step into a scalar is an error (status 5, message
# on stderr). Strings print raw, numbers, true, false and null as jq prints them, objects and
# lists as compact JSON.
# field_opt FILE PATH: the same, but "-" for anything absent.
_field() {
    jq -r --arg p "$2" --arg miss "$3" '
      def step($k):
        if type == "object" then (if has($k) then .[$k] else error("no key " + $k) end)
        elif type == "array" and ($k | test("^[0-9]+$")) and ($k | tonumber) < length then .[$k | tonumber]
        else error("cannot take " + $k + " of a " + type) end;
      (try reduce ($p | split(".")[]) as $k (.; step($k))
       catch (if $miss == "" then error("field " + $p + ": " + .) else "-" end))
      | if type == "object" or type == "array" then tojson else . end' "$1"
}
field() { _field "$1" "$2" ""; }
field_opt() { _field "$1" "$2" "-"; }
