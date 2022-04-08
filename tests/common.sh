INTERACTIVE=1

begin_test() {
    while getopts "d" flag
    do
        case "${flag}" in
            d) INTERACTIVE=0;;
        esac
    done

    # Stop anything currently running
    ./tests/kill-test.sh

    # Remove logs
    rm -rf logs
    mkdir logs
}

end_test() {
    if [[ $INTERACTIVE == 1 ]]
    then
        # Wait for nohup.out to be created
        sleep 1

        tail -f logs/$(hostname).nohup.out
    fi
}
