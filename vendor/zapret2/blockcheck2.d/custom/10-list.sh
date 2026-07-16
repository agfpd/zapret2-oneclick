LIST_HTTP="${LIST_HTTP:-$TESTDIR/list_http.txt}"
LIST_HTTPS_TLS12="${LIST_HTTPS_TLS12:-$TESTDIR/list_https_tls12.txt}"
LIST_HTTPS_TLS13="${LIST_HTTPS_TLS13:-$TESTDIR/list_https_tls13.txt}"
LIST_QUIC="${LIST_QUIC:-$TESTDIR/list_quic.txt}"

check_list()
{
	# $1 - test function
	# $2 - domain
	# $3 - file

	local line ok=0 successes=0 target_successes
	target_successes=${QUICK_MAX_SUCCESSES:-2}
	[ -f "$3" ] || {
		echo "no strategy file '$3'"
		return 1
	}
	while IFS= read -r line; do
		case "$line" in
			""|\#*) continue ;;
		esac
		line=$(echo "$line" | tr -d "\r\n")
		if eval pktws_curl_test_update "$1" "$2" $line; then
			ok=1
			successes=$(($successes+1))
			[ "$SCANLEVEL" = quick ] && [ "$successes" -ge "$target_successes" ] && break
		fi
	done < "$3"

	[ "$ok" = 1 ]
}

pktws_check_http()
{
	# $1 - test function
	# $2 - domain

	check_list "$1" "$2" "$LIST_HTTP"
}

pktws_check_https_tls12()
{
	# $1 - test function
	# $2 - domain

	check_list "$1" "$2" "$LIST_HTTPS_TLS12"
}

pktws_check_https_tls13()
{
	# $1 - test function
	# $2 - domain

	check_list "$1" "$2" "$LIST_HTTPS_TLS13"
}

pktws_check_http3()
{
	# $1 - test function
	# $2 - domain

	check_list "$1" "$2" "$LIST_QUIC"
}
