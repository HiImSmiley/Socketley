# The ok and bad lines a test's own script prints, counted by the test's ok and bad -- only ever sourced.

# A script that stopped on an exception is a failure, since every check after the one it stopped at never ran.
tally() {
    while IFS= read -r line; do
        case "$line" in
            ok\ *) ok ;;
            bad\ *) bad "${line#bad }" "" ;;
            Traceback*|SyntaxError:*) echo "  $line"; bad "the script ran to its end" "it stopped on an exception" ;;
            *) echo "  $line" ;;
        esac
    done
}
