#!/bin/sh
TIMEOUT=15
QUIET=0
SKIP_VERIFY_TLS=

echoerr() {
  if [ "$QUIET" -ne 1 ]; then printf "%s\n" "$*" 1>&2; fi
}

usage() {
  exitcode="$1"
  cat << USAGE >&2
Usage:
  # $cmdname url [-t timeout] [-- command args]
  $cmdname url [-- command args]
  -q | --quiet                        Do not output any status messages
  -i | --skip_verify_tls                        Do not check tls certificates
  # -t TIMEOUT | --timeout=timeout      Timeout in seconds, zero for no timeout
  -- COMMAND ARGS                     Execute command with args after the test finishes
USAGE
  exit "$exitcode"
}

wait_for() {
  command="$*"
  while :
  do
  # for i in `seq $TIMEOUT` ; do
    result=$(curl ${SKIP_VERIFY_TLS} -sL -w "%{http_code}\\n" ${URL} -o /dev/null --connect-timeout 3 --max-time 5)
    if [ $result -eq 200 ] ; then
      if [ -n "$command" ] ; then
        exec $command
      fi
      exit 0
    fi
    if [ "$QUIET" -ne 1 ]; then echo "Waiting for [${URL}] ..."; fi
    sleep 1
  done
  echo "Operation timed out" >&2
  exit 1
}

while [ $# -gt 0 ]
do
  case "$1" in
    http*://* )
    URL=$1
    shift 1
    ;;
    -q | --quiet)
    QUIET=1
    shift 1
    ;;
    -i | --skip_verify_tls)
    SKIP_VERIFY_TLS=-k
    shift 1
    ;;
    -t)
    TIMEOUT="$2"
    if [ "$TIMEOUT" = "" ]; then break; fi
    shift 2
    ;;
    --timeout=*)
    TIMEOUT="${1#*=}"
    shift 1
    ;;
    --)
    shift
    break
    ;;
    --help)
    usage 0
    ;;
    *)
    echoerr "Unknown argument: $1"
    usage 1
    ;;
  esac
done

if [ "$URL" = "" ]; then
  echoerr "Error: you need to provide an url to test."
  usage 2
fi

wait_for "$@"