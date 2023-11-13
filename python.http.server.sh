#!/bin/bash

log_prefix=
stay_quiet=0

# this function reads the header lines from the piped input and formats it into JSON data
parse_headers() {
    request_headers_json="[${spacers[nl]}"

    # reading headers
    while read header_line
    do
        # request lines are separated by a carriage return ('\r') instead of a line-feed ('\n') so removing the trailing '\r's
        header="${header_line%%$'\r'}"

        # if the header is empty/blank line then that means all the headers have been read
        ([ -z "$header" ] || [ "$header" = "" ] || [ ${#header} -eq 0 ]) && break

        # backslash-escaping all the quotation marks, i.e. from '"' to '\"'
        header="${header//\"/\\\"}"

        request_headers_json="$request_headers_json${spacers[t2]}[${spacers[nl]}${spacers[t3]}\"${header/: /\",${spacers[nl]}${spacers[t3]}\"}\"${spacers[nl]}${spacers[t2]}],${spacers[nl]}" # output: [["Content-Type","application/json"], ...]
        #request_headers_json="$request_headers_json${spacers[t2]}{${spacers[nl]}${spacers[t3]}\"name\":${spacers[sp]}\"${header/: /\",${spacers[nl]}${spacers[t3]}\"value\":${spacers[sp]}\"}\"${spacers[nl]}${spacers[t2]}},${spacers[nl]}" # output: [{"name":"Content-Type","value":"application/json"}, ...]
    done

    echo -n "${request_headers_json%,${spacers[nl]}}${spacers[nl]}${spacers[t1]}]"
}

# this function extracts the query-string from the path value and formats it into JSON data
parse_query_params() {
    tmp="$1?"
    tmp="${tmp#*\?}"
    query_string="${tmp%?}"

    if [ ${#query_string} -gt 0 ]
    then
        # tmp="${query_string//=/\":${spacers[sp]}\"}"
        # query_params_json="${tmp//&/\",${spacers[nl]}${spacers[t2]}\"}"

        declare -A params
        while read -d'&' line
        do
            # when the value in the key-value pair is an array (php query params array notation), i.e. when the $line matches '[]=' regular expression
            if [[ "$line" =~ "[]=" ]]
            then
                key="${line%[]=*}"

                # fetching the value of the key from the associative array, if already declared
                # if no value is declared then initializing it with a '['
                previous_value="${params[$key]:-[${spacers[nl]}}"

                # substituting the trailing bracket ']' (if it exists) with a comma ','
                previous_value="${previous_value/%${spacers[nl]}${spacers[t2]}]/,${spacers[nl]}}"

                new_value="${line#*[]=}"
                # replacing replacing '+' with ' '
                new_value="${new_value//+/ }"
                # escaping all the quotation marks
                new_value="${new_value//\"/\\\"}"

                new_value="${spacers[t3]}\"$new_value\"${spacers[nl]}${spacers[t2]}]"

                params["$key"]="$previous_value$new_value"
            else
                key="${line%=*}"
                value="${line#*=}"
                # escaping all the quotation marks
                value="${value//\"/\\\"}"
                # also replacing replacing '+' with ' '
                params["$key"]="\"${value//+/ }\""
            fi
        done <<<"$query_string&"

        query_params_json="{${spacers[nl]}"

        for key in "${!params[@]}"
        do
            query_params_json="$query_params_json${spacers[t2]}\"$key\":${spacers[sp]}${params[$key]},${spacers[nl]}"
        done

        echo -n "${query_params_json%,${spacers[nl]}}${spacers[nl]}${spacers[t1]}}"
    fi
}

list_directory_contents() {
    items=`ls -qgohapN --group-directories-first --time-style=long-iso "$1" | 
    sed -E '
    # delete the first line that outputs the total
    1d;

    # replace all the quotation marks with its equivalent html-symbol-entity: &quot;
    s/"/\&quot;/g;
    
    # if the entry ends with a slash(/) then it is a directory
    /\/$/{
        # format all the directorie/folder entries as an html-table row with the folder icon
        s/[^ ]+ +[^ ]+ +([^ ]+) +([^ ]+) +([^ ]+) +(.+)\//<tr><td><svg width="15" height="15" viewBox="0 0 16 16"><path fill="#dbb065" d="M0.5 13.5L0.5 1.5 4.793 1.5 6.793 3.5 15.5 3.5 15.5 13.5z"><\/path><path fill="#967a44" d="M4.586,2l1.707,1.707L6.586,4H7h8v9H1V2H4.586 M5,1H0v13h16V3H7L5,1L5,1z"><\/path><g><path fill="#f5ce85" d="M0.5 14.5L0.5 4.5 5.118 4.5 7.118 3.5 15.5 3.5 15.5 14.5z"><\/path><path fill="#967a44" d="M15,4v10H1V5h4h0.236l0.211-0.106L7.236,4H15 M16,3H7L5,4H0v11h16V3L16,3z"><\/path><\/g><\/svg><\/td><td><strong><a href="\4\/">\4\/<\/a><\/strong><\/td><td>\2 \3<\/td><td><\/td><\/tr>/;

        # stop processing the script any further and move on with the new entry/line
        b
    };

    # format all the file entries as an html-table row with the file icon
    s/[^ ]+ +[^ ]+ +([^ ]+) +([^ ]+) +([^ ]+) +(.+)/<tr><td><svg width="15" height="15" viewBox="4 4 40 40"><path d="M 12.5 4 C 10.032499 4 8 6.0324991 8 8.5 L 8 39.5 C 8 41.967501 10.032499 44 12.5 44 L 35.5 44 C 37.967501 44 40 41.967501 40 39.5 L 40 18.5 A 1.50015 1.50015 0 0 0 39.560547 17.439453 L 39.544922 17.423828 L 26.560547 4.4394531 A 1.50015 1.50015 0 0 0 25.5 4 L 12.5 4 z M 12.5 7 L 24 7 L 24 15.5 C 24 17.967501 26.032499 20 28.5 20 L 37 20 L 37 39.5 C 37 40.346499 36.346499 41 35.5 41 L 12.5 41 C 11.653501 41 11 40.346499 11 39.5 L 11 8.5 C 11 7.6535009 11.653501 7 12.5 7 z M 27 9.1210938 L 34.878906 17 L 28.5 17 C 27.653501 17 27 16.346499 27 15.5 L 27 9.1210938 z"><\/path><\/svg><\/td><td><strong><a href="\4">\4<\/a><\/strong><\/td><td>\2 \3<\/td><td>\1<\/td><\/tr>/
    '`

    cat <<EOF
<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8">
        <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <title>Directory listing for ${1:1}</title>
        <style> 
            table { min-width: max-content; } 
            body { font-family: monospace; } 
            td, th { padding: 0 35px; } 
            td:first-child, th:first-child { padding: 0 12px; }
            td:nth-child(2), th:nth-child(2), td:last-child, th:last-child { padding: 0; }
        </style>
    </head>
    <body>
        <h1>Directory listing for ${1:1}</h1>
        <hr>
        <table>
            <thead>
                <tr>
                    <th></th>
                    <th>Name</th>
                    <th>Last Modified</th>
                    <th>Size</th>
                </tr>
            </thead>
            <tbody>
$items
            </tbody>
        </table>
        <hr>
    </body>
</html>
EOF
}

# this function performs the same operation as does the `decodeURI` function in JavaScript
# (https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/decodeURI)
# Algorithm source: https://en.wikipedia.org/wiki/UTF-8#Encoding
url_decode() {
    declare -A hex_to_bin=(
        [0]=0000
        [1]=0001
        [2]=0010
        [3]=0011
        [4]=0100
        [5]=0101
        [6]=0110
        [7]=0111
        [8]=1000
        [9]=1001
        [A]=1010
        [B]=1011
        [C]=1100
        [D]=1101
        [E]=1110
        [F]=1111
    )
    declare -A bin_to_hex=(
        [0000]=0
        [0001]=1
        [0010]=2
        [0011]=3
        [0100]=4
        [0101]=5
        [0110]=6
        [0111]=7
        [1000]=8
        [1001]=9
        [1010]=A
        [1011]=B
        [1100]=C
        [1101]=D
        [1110]=E
        [1111]=F
    )

    decoded_url=
    bin_code_point=
    expected=0

    # breaking the URL into parts at every occurence of a '%' symbol
    # i.e. 'abc%12' is converted into 'abc\n%12'
    for part in ${1//%/$'\n'%}
    do
        # if the first 3 letters of a `part` does not contain a '%' symbol followed by 2 hexadecimal digits
        # then simply concat the `part` to the `decoded_url` variable else actually decode the part
        if (! [[ "${part:0:3}" =~ %[0-9A-F][0-9A-F] ]])
        then
            decoded_url="$decoded_url$part"
            continue
        fi
        # else: Decoding the `part` from here onwards

        # concatenating the binary representation of the 2 hexadecimal digits of the `part` variable
        bin_byte="${hex_to_bin[${part:1:1}]}${hex_to_bin[${part:2:1}]}"

        if [ $expected -le 0 ]
        then
            bin_byte="${bin_byte#1*0}"
            byte_length=${#bin_byte}

            # utf-8 bytes to be expected in the following iterations
            expected=$(( 6 - byte_length ))
        else
            bin_byte="${bin_byte#10}"

            # decrementing the number of expected bytes before processing each part
            expected=$(( --expected ))
        fi

        bin_code_point="$bin_code_point$bin_byte"

        if [ $expected -le 0 ]
        then
            code_point=

            # prepending 4 zeroes to account for the last remaining non-4-digit binary value(if any exists)
            bin_code_point="0000$bin_code_point"
            
            while [ ${#bin_code_point} -ge 4 ]
            do
                # extracting the last 4 binary digits(nibble) from `bin_code_point`
                nibble="${bin_code_point: -4}"
                bin_code_point="${bin_code_point%$nibble}"

                # concatenating the hexadecimal representation of each binary-nibble to form a unicode-codepoint
                code_point="${bin_to_hex[$nibble]}$code_point"
            done

            # converting the unicode code-point into a 4-digit value if it isn't already a 4-digit value
            code_point="0000$code_point"

            # concatenating the 4 digits of the unicode code point and the remaining characters from `part`
            decoded_url="$decoded_url\u${code_point: -4}${part:3}"
            bin_code_point=
        fi
    done

    echo -en "$decoded_url"
}

obtain_mime() {
    filename="${1##*/}"
    extension="${filename##*.}"

    # if there is no file-extension then simply return 'application/octet-stream'
    [ "$filename" = "$extension" ] && echo -n "application/octet-stream" && return
    
    # find the mime type from the list of available mime-types
    potential_mime=`grep -Pm 1 "[=,]$extension(,|$)" <<<"$mimes" | cut -d'=' -f1`
    
    # if no mime-type found then simply return 'application/octet-stream'
    ([ -z "$potential_mime" ] || [ "$potential_mime" = "" ] || [ ${#potential_mime} -eq 0 ]) && echo -n "application/octet-stream" && return

    # else return the found mime
    echo -n "$potential_mime"
}

file_not_found_page() {
    cat <<EOF
<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8">
        <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <title>Error 404 Not Found</title>
    </head>
    <body>
        <h1>Not Found</h1>
        <hr>
        <p>
        Error code: <strong>404</strong>
        <br>
        Message: <strong>File Not Found</strong>
        <br>
        <br>
        The requested resource at URL <strong>${1:1}</strong> was not found on this server.
        </p>
        <hr>
    </body>
</html>
EOF
}

request_handler() {
    read method raw_path protocol

    # cleaning up the protocol value from any trailing carriage return ('\r') symbols
    protocol=${protocol%%$'\r'}

    fs_path=.`url_decode "$raw_path"`
    query_params=`parse_query_params "$fs_path"`

    # removing the query parameters (if it exists) from the path otherwise setting it to an empty object
    [ ${#query_params} -gt 0 ] && fs_path="${fs_path%%\?*}" || query_params='{}'

    request_headers=`parse_headers`

    response_code=200
    mime=text/html
    if [ -f "$fs_path" ] && [ -r "$fs_path" ]
    then
        content=`cat "$fs_path"`
        mime=`obtain_mime "$fs_path"`
    elif [ -d "$fs_path" ]
    then
        if [ -f "${fs_path%/}/index.html" ]
        then
            content=`cat "${fs_path%/}"/index.html`
        elif [ -f "${fs_path%/}/index.htm" ]
        then
            content=`cat "${fs_path%/}"/index.htm`
        else
            content=`list_directory_contents "$fs_path"`
        fi
    else
        content=`file_not_found_page "$fs_path"`
        response_code=404
    fi

    # mime=application/json
    # content="{${spacers[nl]}${spacers[t1]}\"method\":${spacers[sp]}\"$method\",${spacers[nl]}${spacers[t1]}\"protocol\":${spacers[sp]}\"$protocol\",${spacers[nl]}${spacers[t1]}\"raw_path\":${spacers[sp]}\"$raw_path\",${spacers[nl]}${spacers[t1]}\"path\":${spacers[sp]}\"${fs_path#.}\",${spacers[nl]}${spacers[t1]}\"time\":${spacers[sp]}\"`date --utc +'%FT%T.000Z'`\",${spacers[nl]}${spacers[t1]}\"query_params\":${spacers[sp]}$query_params,${spacers[nl]}${spacers[t1]}\"request_headers\":${spacers[sp]}$request_headers${spacers[nl]}}"

    
    content_length=`wc --bytes <<<"$content"` # "${#content}" is not applicable here are as the content may contain certain characters that are composed of 2 or more bytes
    content_length=$((content_length - 1)) # decremented by one because bash's here-string adds an extra unnecessary newline at the end which is not actually there in the original `content`

    response="Server: Bash/101\nDate: $time_now\nContent-Length: $content_length\nContent-type: $mime\n\n$content"

    # logfile format inspired by https://github.com/python/cpython/blob/main/Lib/http/server.py#L58,L78
    [ $stay_quiet -eq 0 ] && printf '%s [%s %s] "%s %s %s" %d %d\n' "$log_prefix" `date +"%d/%b/%Y %T"` "$method" "$raw_path" "$protocol" $response_code `wc --bytes <<<"$response"` # ${#response}

    echo -e "HTTP/1.0 $response_code ${response_status[$response_code]}\n$response" > http_response
}

# defining the CommandLine Interface options and flags
# refer to getopt example at /usr/share/doc/util-linux/getopt-example.bash and getopt manual
TEMP=`getopt --options 'hb:cd:qt:' --long 'help,bind:,compact,directory:,quiet,tab-width:' --name "$0" -- "$@"`

[ $? -ne 0 ] && echo "USAGE: $0 [-h | --help] [-b ADDRESS | --bind=ADDRESS] [-q | --quiet] [-c | --compact] [-d DIRECTORY | --directory=DIRECTORY] [-t WIDTH | --tab-width=WIDTH] [PORT]" >&2 && exit 1

eval set -- "$TEMP"
unset TEMP

# initializing variables that are relevant for running the server
declare -A spacers=(
    [nl]=$'\n' # newline
    [sp]=' '   # space
)
declare -A response_status=(
    [200]="OK"
    [404]="Not Found"
)
declare -A status_codes=(
    [8]="520 Web Server Returned an Unknown Error"
    [9]="521 Web Server Is Down"
    [10]="522 Connection Timed Out"
    [11]="523 Origin Is Unreachable"
    [12]="524 A Timeout Occurred"
    [13]="525 SSL Handshake Failed"
    [14]="526 Invalid SSL Certificate"
    [15]="527 Railgun Error"
    [17]="529 Site is overloaded"
    [18]="530 Site is frozen"
    [43]="299 Miscellaneous Persistent Warning"
    [44]="300 Multiple Choices"
    [45]="301 Moved Permanently"
    [46]="302 Found"
    [47]="303 See Other"
    [48]="304 Not Modified"
    [49]="305 Use Proxy"
    [50]="306 Switch Proxy"
    [51]="307 Temporary Redirect"
    [52]="308 Permanent Redirect"
    [86]="598 Network read timeout error"
    [87]="599 Network Connect Timeout Error"
    [100]="100 Continue"
    [101]="101 Switching Protocols"
    [102]="102 Processing"
    [103]="103 Early Hints"
    [110]="110 Response is Stale"
    [111]="111 Revalidation Failed"
    [112]="112 Disconnected Operation"
    [113]="113 Heuristic Expiration"
    [144]="400 Bad Request"
    [145]="401 Unauthorized"
    [146]="402 Payment Required"
    [147]="403 Forbidden"
    [148]="404 Not Found"
    [149]="405 Method Not Allowed"
    [150]="406 Not Acceptable"
    [151]="407 Proxy Authentication Required"
    [152]="408 Request Timeout"
    [153]="409 Conflict"
    [154]="410 Gone"
    [155]="411 Length Required"
    [156]="412 Precondition Failed"
    [157]="413 Payload Too Large"
    [158]="414 URI Too Long"
    [159]="415 Unsupported Media Type"
    [160]="416 Range Not Satisfiable"
    [161]="417 Expectation Failed"
    [162]="418 I'm a teapot"
    [163]="419 Page Expired"
    [164]="420 Method Failure"
    [165]="421 Misdirected Request"
    [166]="422 Unprocessable Entity"
    [167]="423 Locked"
    [168]="424 Failed Dependency"
    [169]="425 Too Early"
    [170]="426 Upgrade Required"
    [172]="428 Precondition Required"
    [173]="429 Too Many Requests"
    [174]="430 Request Header Fields Too Large"
    [175]="431 Request Header Fields Too Large"
    [184]="440 Login Time-out"
    [188]="444 No Response"
    [193]="449 Retry With"
    [194]="450 Blocked by Windows Parental Controls"
    [195]="451 Unavailable For Legal Reasons"
    [199]="199 Miscellaneous Warning"
    [200]="200 OK"
    [201]="201 Created"
    [202]="202 Accepted"
    [203]="203 Non-Authoritative Information"
    [204]="204 No Content"
    [205]="205 Reset Content"
    [206]="206 Partial Content"
    [207]="207 Multi-Status"
    [208]="208 Already Reported"
    [214]="214 Transformation Applied"
    [218]="218 This is fine"
    [226]="226 IM Used"
    [238]="494 Request header too large"
    [239]="495 SSL Certificate Error"
    [240]="496 SSL Certificate Required"
    [241]="497 HTTP Request Sent to HTTPS Port"
    [242]="498 Invalid Token"
    [243]="499 Client Closed Request"
    [244]="500 Internal Server Error"
    [245]="501 Not Implemented"
    [246]="502 Bad Gateway"
    [247]="503 Service Unavailable"
    [248]="504 Gateway Timeout"
    [249]="505 HTTP Version Not Supported"
    [250]="506 Variant Also Negotiates"
    [251]="507 Insufficient Storage"
    [252]="508 Loop Detected"
    [253]="509 Bandwidth Limit Exceeded"
    [254]="510 Not Extended"
    [255]="511 Network Authentication Required"
)
tab_width=2
addr=

while true; do
    case $1 in
        "-h"|"--help")
            indent="        `printf "%${#0}.s"`"
            cat <<EOF
USAGE: $0 [-h | --help] [-b ADDRESS | --bind=ADDRESS] [-q | --quiet]
$indent[-c | --compact] [-d DIRECTORY | --directory=DIRECTORY]
$indent[-t WIDTH | --tab-width=WIDTH] [PORT]

positional arguments:
  PORT                  use PORT as a port to listen on (default: 4000)

options:
  -h, --help            show this help message and exit
  -b ADDRESS, --bind=ADDRESS
                        use ADDRESS as alternate bind IP address (default for all interfaces)
  -c, --compact         outputs the JSONified request in compact/compressed form
  -d DIRECTORY, --directory=DIRECTORY
                        user DIRECTORY as an alternate directory to start the HTTP server from
                        (default: current directory)
  -q, --quiet           start the server but do not print any logs to stdout. Use it twice to
                        also suppress printing of any errors to stderr
  -t WIDTH, --tab-width=WIDTH
                        JSON data formatted with an indentation of WIDTH spaces will be
                        outputted. This option will take not effect on the output if used
                        along with \`--compact\` flag. (default: 2)

EOF
            exit;
        ;;
        "-c"|"--compact")
            tab_width=0
            spacers[nl]=''
            spacers[sp]=''
            shift
            continue
        ;;
        "-d"|"--directory")
            [ -d "$2" ] && cd "$2"

            shift 2
            continue
        ;;
        "-t"|"--tab-width")
            # this flag will not work if --compact is already defined or if non-integer input is given
            [ $tab_width -gt 0 ] && [ "${2//[[:digit:]]}" = "" ] && tab_width=$2
            shift 2
            continue
        ;;
        "-b"|"--bind")
            addr=`sed -E '/^([0-9]+\.){3}[0-9]+$/{s/\.0+([1-9])/.\1/g; q;}; s/.*/0/;' <<<"$2"`

            # checking if the provided address contains 4 integers seperated by period ('.')
            [ "$addr" = "0" ] && echo "$0: provided bind IP address is not in a valid format: $2" >&2 && exit 1

            # checking if the address is a valid IPv4 address by checking if each number lies in the range [0, 255]
            is_valid=`sed -E 's/[0-9]+/& >= 0 \&\& & < 256/g; s/\./ \&\& /g' <<<"$addr" | bc`

            [ $is_valid -eq 0 ] && echo "$0: provided bind IP address is not a valid IPv4 address: $2" >&2 && exit 1
            
            shift 2
            continue
        ;;
        "-q"|"--quiet")
            # defining the logging level by incrementing the `stay_quiet` value, everytime this flag is called
            stay_quiet=$((stay_quiet + 1))

            # max incrementable value is 2
            [ $stay_quiet -gt 2 ] && stay_quiet=2

            shift
            continue
        ;;
        '--')
            shift
            break
        ;;
        *)
            echo 'Internal error!' >&2
            exit 1
        ;;
    esac
done

# adding different levelled (3 levels only) indentation-tabs to the `spacers` array
for i in {1..3}
do
    spacers["t$i"]="`seq $i | xargs printf "%$tab_width.s" 2> /dev/null`"
done

port=${1:-4000}

# checking if port number is a digit and if it is in a valid range of [0-65535]
! ([ -n "$(grep -Px '\d+' <<<$port)" ] && [ $port -ge 0 ] && [ $port -lt `bc <<<2^16` ]) && echo "$0: invalid port number provided: $1" >&2 && exit 1

# fetching loopback address to use in the logfile output
loopback_address=`ip -br address | grep ^lo | grep -Po '(\d+\.){3}\d+'`

# generating the prefix string to output as logs
log_prefix="${loopback_address:-127.0.0.1} `compgen -c identd > /dev/null && identd || echo -` `[ $EUID -eq $(id -u) ] && echo - || id -nu`"

[ $stay_quiet -eq 0 ] && echo -e "Listening on port $port (http://${addr:-0.0.0.0}:$port/)...\n"

addr=${addr:+--source=$addr}

# Loading all the file-mime-types there can possibly be.
# The following list was generated through the undermentioned one-liner:
# wget --output-document=- https://cdn.jsdelivr.net/npm/mime-db/db.json | sed -En '/^    "extensions": \[/{s/.+\["|"\],?//g; s/", ?"/,/g; x; G; s/\n/=/; p}; /^  "/{s/^  "([^"]+)".+/\1/; h}'
mimes='application/andrew-inset=ez
application/applixware=aw
application/atom+xml=atom
application/atomcat+xml=atomcat
application/atomdeleted+xml=atomdeleted
application/atomsvc+xml=atomsvc
application/atsc-dwd+xml=dwd
application/atsc-held+xml=held
application/atsc-rsat+xml=rsat
application/bdoc=bdoc
application/calendar+xml=xcs
application/ccxml+xml=ccxml
application/cdfx+xml=cdfx
application/cdmi-capability=cdmia
application/cdmi-container=cdmic
application/cdmi-domain=cdmid
application/cdmi-object=cdmio
application/cdmi-queue=cdmiq
application/cpl+xml=cpl
application/cu-seeme=cu
application/dash+xml=mpd
application/dash-patch+xml=mpp
application/davmount+xml=davmount
application/docbook+xml=dbk
application/dssc+der=dssc
application/dssc+xml=xdssc
application/ecmascript=es,ecma
application/emma+xml=emma
application/emotionml+xml=emotionml
application/epub+zip=epub
application/exi=exi
application/express=exp
application/fdt+xml=fdt
application/font-tdpfr=pfr
application/geo+json=geojson
application/gml+xml=gml
application/gpx+xml=gpx
application/gxf=gxf
application/gzip=gz
application/hjson=hjson
application/hyperstudio=stk
application/inkml+xml=ink,inkml
application/ipfix=ipfix
application/its+xml=its
application/java-archive=jar,war,ear
application/java-serialized-object=ser
application/java-vm=class
application/javascript=js,mjs
application/json=json,map
application/json5=json5
application/jsonml+json=jsonml
application/ld+json=jsonld
application/lgr+xml=lgr
application/lost+xml=lostxml
application/mac-binhex40=hqx
application/mac-compactpro=cpt
application/mads+xml=mads
application/manifest+json=webmanifest
application/marc=mrc
application/marcxml+xml=mrcx
application/mathematica=ma,nb,mb
application/mathml+xml=mathml
application/mbox=mbox
application/media-policy-dataset+xml=mpf
application/mediaservercontrol+xml=mscml
application/metalink+xml=metalink
application/metalink4+xml=meta4
application/mets+xml=mets
application/mmt-aei+xml=maei
application/mmt-usd+xml=musd
application/mods+xml=mods
application/mp21=m21,mp21
application/mp4=mp4s,m4p
application/msword=doc,dot
application/mxf=mxf
application/n-quads=nq
application/n-triples=nt
application/node=cjs
application/octet-stream=bin,dms,lrf,mar,so,dist,distz,pkg,bpk,dump,elc,deploy,exe,dll,deb,dmg,iso,img,msi,msp,msm,buffer
application/oda=oda
application/oebps-package+xml=opf
application/ogg=ogx
application/omdoc+xml=omdoc
application/onenote=onetoc,onetoc2,onetmp,onepkg
application/oxps=oxps
application/p2p-overlay+xml=relo
application/patch-ops-error+xml=xer
application/pdf=pdf
application/pgp-encrypted=pgp
application/pgp-keys=asc
application/pgp-signature=asc,sig
application/pics-rules=prf
application/pkcs10=p10
application/pkcs7-mime=p7m,p7c
application/pkcs7-signature=p7s
application/pkcs8=p8
application/pkix-attr-cert=ac
application/pkix-cert=cer
application/pkix-crl=crl
application/pkix-pkipath=pkipath
application/pkixcmp=pki
application/pls+xml=pls
application/postscript=ai,eps,ps
application/provenance+xml=provx
application/prs.cww=cww
application/pskc+xml=pskcxml
application/raml+yaml=raml
application/rdf+xml=rdf,owl
application/reginfo+xml=rif
application/relax-ng-compact-syntax=rnc
application/resource-lists+xml=rl
application/resource-lists-diff+xml=rld
application/rls-services+xml=rs
application/route-apd+xml=rapd
application/route-s-tsid+xml=sls
application/route-usd+xml=rusd
application/rpki-ghostbusters=gbr
application/rpki-manifest=mft
application/rpki-roa=roa
application/rsd+xml=rsd
application/rss+xml=rss
application/rtf=rtf
application/sbml+xml=sbml
application/scvp-cv-request=scq
application/scvp-cv-response=scs
application/scvp-vp-request=spq
application/scvp-vp-response=spp
application/sdp=sdp
application/senml+xml=senmlx
application/sensml+xml=sensmlx
application/set-payment-initiation=setpay
application/set-registration-initiation=setreg
application/shf+xml=shf
application/sieve=siv,sieve
application/smil+xml=smi,smil
application/sparql-query=rq
application/sparql-results+xml=srx
application/srgs=gram
application/srgs+xml=grxml
application/sru+xml=sru
application/ssdl+xml=ssdl
application/ssml+xml=ssml
application/swid+xml=swidtag
application/tei+xml=tei,teicorpus
application/thraud+xml=tfi
application/timestamped-data=tsd
application/toml=toml
application/trig=trig
application/ttml+xml=ttml
application/ubjson=ubj
application/urc-ressheet+xml=rsheet
application/urc-targetdesc+xml=td
application/vnd.1000minds.decision-model+xml=1km
application/vnd.3gpp.pic-bw-large=plb
application/vnd.3gpp.pic-bw-small=psb
application/vnd.3gpp.pic-bw-var=pvb
application/vnd.3gpp2.tcap=tcap
application/vnd.3m.post-it-notes=pwn
application/vnd.accpac.simply.aso=aso
application/vnd.accpac.simply.imp=imp
application/vnd.acucobol=acu
application/vnd.acucorp=atc,acutc
application/vnd.adobe.air-application-installer-package+zip=air
application/vnd.adobe.formscentral.fcdt=fcdt
application/vnd.adobe.fxp=fxp,fxpl
application/vnd.adobe.xdp+xml=xdp
application/vnd.adobe.xfdf=xfdf
application/vnd.age=age
application/vnd.ahead.space=ahead
application/vnd.airzip.filesecure.azf=azf
application/vnd.airzip.filesecure.azs=azs
application/vnd.amazon.ebook=azw
application/vnd.americandynamics.acc=acc
application/vnd.amiga.ami=ami
application/vnd.android.package-archive=apk
application/vnd.anser-web-certificate-issue-initiation=cii
application/vnd.anser-web-funds-transfer-initiation=fti
application/vnd.antix.game-component=atx
application/vnd.apple.installer+xml=mpkg
application/vnd.apple.keynote=key
application/vnd.apple.mpegurl=m3u8
application/vnd.apple.numbers=numbers
application/vnd.apple.pages=pages
application/vnd.apple.pkpass=pkpass
application/vnd.aristanetworks.swi=swi
application/vnd.astraea-software.iota=iota
application/vnd.audiograph=aep
application/vnd.balsamiq.bmml+xml=bmml
application/vnd.blueice.multipass=mpm
application/vnd.bmi=bmi
application/vnd.businessobjects=rep
application/vnd.chemdraw+xml=cdxml
application/vnd.chipnuts.karaoke-mmd=mmd
application/vnd.cinderella=cdy
application/vnd.citationstyles.style+xml=csl
application/vnd.claymore=cla
application/vnd.cloanto.rp9=rp9
application/vnd.clonk.c4group=c4g,c4d,c4f,c4p,c4u
application/vnd.cluetrust.cartomobile-config=c11amc
application/vnd.cluetrust.cartomobile-config-pkg=c11amz
application/vnd.commonspace=csp
application/vnd.contact.cmsg=cdbcmsg
application/vnd.cosmocaller=cmc
application/vnd.crick.clicker=clkx
application/vnd.crick.clicker.keyboard=clkk
application/vnd.crick.clicker.palette=clkp
application/vnd.crick.clicker.template=clkt
application/vnd.crick.clicker.wordbank=clkw
application/vnd.criticaltools.wbs+xml=wbs
application/vnd.ctc-posml=pml
application/vnd.cups-ppd=ppd
application/vnd.curl.car=car
application/vnd.curl.pcurl=pcurl
application/vnd.dart=dart
application/vnd.data-vision.rdz=rdz
application/vnd.dbf=dbf
application/vnd.dece.data=uvf,uvvf,uvd,uvvd
application/vnd.dece.ttml+xml=uvt,uvvt
application/vnd.dece.unspecified=uvx,uvvx
application/vnd.dece.zip=uvz,uvvz
application/vnd.denovo.fcselayout-link=fe_launch
application/vnd.dna=dna
application/vnd.dolby.mlp=mlp
application/vnd.dpgraph=dpg
application/vnd.dreamfactory=dfac
application/vnd.ds-keypoint=kpxx
application/vnd.dvb.ait=ait
application/vnd.dvb.service=svc
application/vnd.dynageo=geo
application/vnd.ecowin.chart=mag
application/vnd.enliven=nml
application/vnd.epson.esf=esf
application/vnd.epson.msf=msf
application/vnd.epson.quickanime=qam
application/vnd.epson.salt=slt
application/vnd.epson.ssf=ssf
application/vnd.eszigno3+xml=es3,et3
application/vnd.ezpix-album=ez2
application/vnd.ezpix-package=ez3
application/vnd.fdf=fdf
application/vnd.fdsn.mseed=mseed
application/vnd.fdsn.seed=seed,dataless
application/vnd.flographit=gph
application/vnd.fluxtime.clip=ftc
application/vnd.framemaker=fm,frame,maker,book
application/vnd.frogans.fnc=fnc
application/vnd.frogans.ltf=ltf
application/vnd.fsc.weblaunch=fsc
application/vnd.fujitsu.oasys=oas
application/vnd.fujitsu.oasys2=oa2
application/vnd.fujitsu.oasys3=oa3
application/vnd.fujitsu.oasysgp=fg5
application/vnd.fujitsu.oasysprs=bh2
application/vnd.fujixerox.ddd=ddd
application/vnd.fujixerox.docuworks=xdw
application/vnd.fujixerox.docuworks.binder=xbd
application/vnd.fuzzysheet=fzs
application/vnd.genomatix.tuxedo=txd
application/vnd.geogebra.file=ggb
application/vnd.geogebra.tool=ggt
application/vnd.geometry-explorer=gex,gre
application/vnd.geonext=gxt
application/vnd.geoplan=g2w
application/vnd.geospace=g3w
application/vnd.gmx=gmx
application/vnd.google-apps.document=gdoc
application/vnd.google-apps.presentation=gslides
application/vnd.google-apps.spreadsheet=gsheet
application/vnd.google-earth.kml+xml=kml
application/vnd.google-earth.kmz=kmz
application/vnd.grafeq=gqf,gqs
application/vnd.groove-account=gac
application/vnd.groove-help=ghf
application/vnd.groove-identity-message=gim
application/vnd.groove-injector=grv
application/vnd.groove-tool-message=gtm
application/vnd.groove-tool-template=tpl
application/vnd.groove-vcard=vcg
application/vnd.hal+xml=hal
application/vnd.handheld-entertainment+xml=zmm
application/vnd.hbci=hbci
application/vnd.hhe.lesson-player=les
application/vnd.hp-hpgl=hpgl
application/vnd.hp-hpid=hpid
application/vnd.hp-hps=hps
application/vnd.hp-jlyt=jlt
application/vnd.hp-pcl=pcl
application/vnd.hp-pclxl=pclxl
application/vnd.hydrostatix.sof-data=sfd-hdstx
application/vnd.ibm.minipay=mpy
application/vnd.ibm.modcap=afp,listafp,list3820
application/vnd.ibm.rights-management=irm
application/vnd.ibm.secure-container=sc
application/vnd.iccprofile=icc,icm
application/vnd.igloader=igl
application/vnd.immervision-ivp=ivp
application/vnd.immervision-ivu=ivu
application/vnd.insors.igm=igm
application/vnd.intercon.formnet=xpw,xpx
application/vnd.intergeo=i2g
application/vnd.intu.qbo=qbo
application/vnd.intu.qfx=qfx
application/vnd.ipunplugged.rcprofile=rcprofile
application/vnd.irepository.package+xml=irp
application/vnd.is-xpr=xpr
application/vnd.isac.fcs=fcs
application/vnd.jam=jam
application/vnd.jcp.javame.midlet-rms=rms
application/vnd.jisp=jisp
application/vnd.joost.joda-archive=joda
application/vnd.kahootz=ktz,ktr
application/vnd.kde.karbon=karbon
application/vnd.kde.kchart=chrt
application/vnd.kde.kformula=kfo
application/vnd.kde.kivio=flw
application/vnd.kde.kontour=kon
application/vnd.kde.kpresenter=kpr,kpt
application/vnd.kde.kspread=ksp
application/vnd.kde.kword=kwd,kwt
application/vnd.kenameaapp=htke
application/vnd.kidspiration=kia
application/vnd.kinar=kne,knp
application/vnd.koan=skp,skd,skt,skm
application/vnd.kodak-descriptor=sse
application/vnd.las.las+xml=lasxml
application/vnd.llamagraphics.life-balance.desktop=lbd
application/vnd.llamagraphics.life-balance.exchange+xml=lbe
application/vnd.lotus-1-2-3=123
application/vnd.lotus-approach=apr
application/vnd.lotus-freelance=pre
application/vnd.lotus-notes=nsf
application/vnd.lotus-organizer=org
application/vnd.lotus-screencam=scm
application/vnd.lotus-wordpro=lwp
application/vnd.macports.portpkg=portpkg
application/vnd.mapbox-vector-tile=mvt
application/vnd.mcd=mcd
application/vnd.medcalcdata=mc1
application/vnd.mediastation.cdkey=cdkey
application/vnd.mfer=mwf
application/vnd.mfmp=mfm
application/vnd.micrografx.flo=flo
application/vnd.micrografx.igx=igx
application/vnd.mif=mif
application/vnd.mobius.daf=daf
application/vnd.mobius.dis=dis
application/vnd.mobius.mbk=mbk
application/vnd.mobius.mqy=mqy
application/vnd.mobius.msl=msl
application/vnd.mobius.plc=plc
application/vnd.mobius.txf=txf
application/vnd.mophun.application=mpn
application/vnd.mophun.certificate=mpc
application/vnd.mozilla.xul+xml=xul
application/vnd.ms-artgalry=cil
application/vnd.ms-cab-compressed=cab
application/vnd.ms-excel=xls,xlm,xla,xlc,xlt,xlw
application/vnd.ms-excel.addin.macroenabled.12=xlam
application/vnd.ms-excel.sheet.binary.macroenabled.12=xlsb
application/vnd.ms-excel.sheet.macroenabled.12=xlsm
application/vnd.ms-excel.template.macroenabled.12=xltm
application/vnd.ms-fontobject=eot
application/vnd.ms-htmlhelp=chm
application/vnd.ms-ims=ims
application/vnd.ms-lrm=lrm
application/vnd.ms-officetheme=thmx
application/vnd.ms-outlook=msg
application/vnd.ms-pki.seccat=cat
application/vnd.ms-pki.stl=stl
application/vnd.ms-powerpoint=ppt,pps,pot
application/vnd.ms-powerpoint.addin.macroenabled.12=ppam
application/vnd.ms-powerpoint.presentation.macroenabled.12=pptm
application/vnd.ms-powerpoint.slide.macroenabled.12=sldm
application/vnd.ms-powerpoint.slideshow.macroenabled.12=ppsm
application/vnd.ms-powerpoint.template.macroenabled.12=potm
application/vnd.ms-project=mpp,mpt
application/vnd.ms-word.document.macroenabled.12=docm
application/vnd.ms-word.template.macroenabled.12=dotm
application/vnd.ms-works=wps,wks,wcm,wdb
application/vnd.ms-wpl=wpl
application/vnd.ms-xpsdocument=xps
application/vnd.mseq=mseq
application/vnd.musician=mus
application/vnd.muvee.style=msty
application/vnd.mynfc=taglet
application/vnd.neurolanguage.nlu=nlu
application/vnd.nitf=ntf,nitf
application/vnd.noblenet-directory=nnd
application/vnd.noblenet-sealer=nns
application/vnd.noblenet-web=nnw
application/vnd.nokia.n-gage.ac+xml=ac
application/vnd.nokia.n-gage.data=ngdat
application/vnd.nokia.n-gage.symbian.install=n-gage
application/vnd.nokia.radio-preset=rpst
application/vnd.nokia.radio-presets=rpss
application/vnd.novadigm.edm=edm
application/vnd.novadigm.edx=edx
application/vnd.novadigm.ext=ext
application/vnd.oasis.opendocument.chart=odc
application/vnd.oasis.opendocument.chart-template=otc
application/vnd.oasis.opendocument.database=odb
application/vnd.oasis.opendocument.formula=odf
application/vnd.oasis.opendocument.formula-template=odft
application/vnd.oasis.opendocument.graphics=odg
application/vnd.oasis.opendocument.graphics-template=otg
application/vnd.oasis.opendocument.image=odi
application/vnd.oasis.opendocument.image-template=oti
application/vnd.oasis.opendocument.presentation=odp
application/vnd.oasis.opendocument.presentation-template=otp
application/vnd.oasis.opendocument.spreadsheet=ods
application/vnd.oasis.opendocument.spreadsheet-template=ots
application/vnd.oasis.opendocument.text=odt
application/vnd.oasis.opendocument.text-master=odm
application/vnd.oasis.opendocument.text-template=ott
application/vnd.oasis.opendocument.text-web=oth
application/vnd.olpc-sugar=xo
application/vnd.oma.dd2+xml=dd2
application/vnd.openblox.game+xml=obgx
application/vnd.openofficeorg.extension=oxt
application/vnd.openstreetmap.data+xml=osm
application/vnd.openxmlformats-officedocument.presentationml.presentation=pptx
application/vnd.openxmlformats-officedocument.presentationml.slide=sldx
application/vnd.openxmlformats-officedocument.presentationml.slideshow=ppsx
application/vnd.openxmlformats-officedocument.presentationml.template=potx
application/vnd.openxmlformats-officedocument.spreadsheetml.sheet=xlsx
application/vnd.openxmlformats-officedocument.spreadsheetml.template=xltx
application/vnd.openxmlformats-officedocument.wordprocessingml.document=docx
application/vnd.openxmlformats-officedocument.wordprocessingml.template=dotx
application/vnd.osgeo.mapguide.package=mgp
application/vnd.osgi.dp=dp
application/vnd.osgi.subsystem=esa
application/vnd.palm=pdb,pqa,oprc
application/vnd.pawaafile=paw
application/vnd.pg.format=str
application/vnd.pg.osasli=ei6
application/vnd.picsel=efif
application/vnd.pmi.widget=wg
application/vnd.pocketlearn=plf
application/vnd.powerbuilder6=pbd
application/vnd.previewsystems.box=box
application/vnd.proteus.magazine=mgz
application/vnd.publishare-delta-tree=qps
application/vnd.pvi.ptid1=ptid
application/vnd.quark.quarkxpress=qxd,qxt,qwd,qwt,qxl,qxb
application/vnd.rar=rar
application/vnd.realvnc.bed=bed
application/vnd.recordare.musicxml=mxl
application/vnd.recordare.musicxml+xml=musicxml
application/vnd.rig.cryptonote=cryptonote
application/vnd.rim.cod=cod
application/vnd.rn-realmedia=rm
application/vnd.rn-realmedia-vbr=rmvb
application/vnd.route66.link66+xml=link66
application/vnd.sailingtracker.track=st
application/vnd.seemail=see
application/vnd.sema=sema
application/vnd.semd=semd
application/vnd.semf=semf
application/vnd.shana.informed.formdata=ifm
application/vnd.shana.informed.formtemplate=itp
application/vnd.shana.informed.interchange=iif
application/vnd.shana.informed.package=ipk
application/vnd.simtech-mindmapper=twd,twds
application/vnd.smaf=mmf
application/vnd.smart.teacher=teacher
application/vnd.software602.filler.form+xml=fo
application/vnd.solent.sdkm+xml=sdkm,sdkd
application/vnd.spotfire.dxp=dxp
application/vnd.spotfire.sfs=sfs
application/vnd.stardivision.calc=sdc
application/vnd.stardivision.draw=sda
application/vnd.stardivision.impress=sdd
application/vnd.stardivision.math=smf
application/vnd.stardivision.writer=sdw,vor
application/vnd.stardivision.writer-global=sgl
application/vnd.stepmania.package=smzip
application/vnd.stepmania.stepchart=sm
application/vnd.sun.wadl+xml=wadl
application/vnd.sun.xml.calc=sxc
application/vnd.sun.xml.calc.template=stc
application/vnd.sun.xml.draw=sxd
application/vnd.sun.xml.draw.template=std
application/vnd.sun.xml.impress=sxi
application/vnd.sun.xml.impress.template=sti
application/vnd.sun.xml.math=sxm
application/vnd.sun.xml.writer=sxw
application/vnd.sun.xml.writer.global=sxg
application/vnd.sun.xml.writer.template=stw
application/vnd.sus-calendar=sus,susp
application/vnd.svd=svd
application/vnd.symbian.install=sis,sisx
application/vnd.syncml+xml=xsm
application/vnd.syncml.dm+wbxml=bdm
application/vnd.syncml.dm+xml=xdm
application/vnd.syncml.dmddf+xml=ddf
application/vnd.tao.intent-module-archive=tao
application/vnd.tcpdump.pcap=pcap,cap,dmp
application/vnd.tmobile-livetv=tmo
application/vnd.trid.tpt=tpt
application/vnd.triscape.mxs=mxs
application/vnd.trueapp=tra
application/vnd.ufdl=ufd,ufdl
application/vnd.uiq.theme=utz
application/vnd.umajin=umj
application/vnd.unity=unityweb
application/vnd.uoml+xml=uoml
application/vnd.vcx=vcx
application/vnd.visio=vsd,vst,vss,vsw
application/vnd.visionary=vis
application/vnd.vsf=vsf
application/vnd.wap.wbxml=wbxml
application/vnd.wap.wmlc=wmlc
application/vnd.wap.wmlscriptc=wmlsc
application/vnd.webturbo=wtb
application/vnd.wolfram.player=nbp
application/vnd.wordperfect=wpd
application/vnd.wqd=wqd
application/vnd.wt.stf=stf
application/vnd.xara=xar
application/vnd.xfdl=xfdl
application/vnd.yamaha.hv-dic=hvd
application/vnd.yamaha.hv-script=hvs
application/vnd.yamaha.hv-voice=hvp
application/vnd.yamaha.openscoreformat=osf
application/vnd.yamaha.openscoreformat.osfpvg+xml=osfpvg
application/vnd.yamaha.smaf-audio=saf
application/vnd.yamaha.smaf-phrase=spf
application/vnd.yellowriver-custom-menu=cmp
application/vnd.zul=zir,zirz
application/vnd.zzazz.deck+xml=zaz
application/voicexml+xml=vxml
application/wasm=wasm
application/watcherinfo+xml=wif
application/widget=wgt
application/winhlp=hlp
application/wsdl+xml=wsdl
application/wspolicy+xml=wspolicy
application/x-7z-compressed=7z
application/x-abiword=abw
application/x-ace-compressed=ace
application/x-apple-diskimage=dmg
application/x-arj=arj
application/x-authorware-bin=aab,x32,u32,vox
application/x-authorware-map=aam
application/x-authorware-seg=aas
application/x-bcpio=bcpio
application/x-bdoc=bdoc
application/x-bittorrent=torrent
application/x-blorb=blb,blorb
application/x-bzip=bz
application/x-bzip2=bz2,boz
application/x-cbr=cbr,cba,cbt,cbz,cb7
application/x-cdlink=vcd
application/x-cfs-compressed=cfs
application/x-chat=chat
application/x-chess-pgn=pgn
application/x-chrome-extension=crx
application/x-cocoa=cco
application/x-conference=nsc
application/x-cpio=cpio
application/x-csh=csh
application/x-debian-package=deb,udeb
application/x-dgc-compressed=dgc
application/x-director=dir,dcr,dxr,cst,cct,cxt,w3d,fgd,swa
application/x-doom=wad
application/x-dtbncx+xml=ncx
application/x-dtbook+xml=dtb
application/x-dtbresource+xml=res
application/x-dvi=dvi
application/x-envoy=evy
application/x-eva=eva
application/x-font-bdf=bdf
application/x-font-ghostscript=gsf
application/x-font-linux-psf=psf
application/x-font-pcf=pcf
application/x-font-snf=snf
application/x-font-type1=pfa,pfb,pfm,afm
application/x-freearc=arc
application/x-futuresplash=spl
application/x-gca-compressed=gca
application/x-glulx=ulx
application/x-gnumeric=gnumeric
application/x-gramps-xml=gramps
application/x-gtar=gtar
application/x-hdf=hdf
application/x-httpd-php=php
application/x-install-instructions=install
application/x-iso9660-image=iso
application/x-iwork-keynote-sffkey=key
application/x-iwork-numbers-sffnumbers=numbers
application/x-iwork-pages-sffpages=pages
application/x-java-archive-diff=jardiff
application/x-java-jnlp-file=jnlp
application/x-keepass2=kdbx
application/x-latex=latex
application/x-lua-bytecode=luac
application/x-lzh-compressed=lzh,lha
application/x-makeself=run
application/x-mie=mie
application/x-mobipocket-ebook=prc,mobi
application/x-ms-application=application
application/x-ms-shortcut=lnk
application/x-ms-wmd=wmd
application/x-ms-wmz=wmz
application/x-ms-xbap=xbap
application/x-msaccess=mdb
application/x-msbinder=obd
application/x-mscardfile=crd
application/x-msclip=clp
application/x-msdos-program=exe
application/x-msdownload=exe,dll,com,bat,msi
application/x-msmediaview=mvb,m13,m14
application/x-msmetafile=wmf,wmz,emf,emz
application/x-msmoney=mny
application/x-mspublisher=pub
application/x-msschedule=scd
application/x-msterminal=trm
application/x-mswrite=wri
application/x-netcdf=nc,cdf
application/x-ns-proxy-autoconfig=pac
application/x-nzb=nzb
application/x-perl=pl,pm
application/x-pilot=prc,pdb
application/x-pkcs12=p12,pfx
application/x-pkcs7-certificates=p7b,spc
application/x-pkcs7-certreqresp=p7r
application/x-rar-compressed=rar
application/x-redhat-package-manager=rpm
application/x-research-info-systems=ris
application/x-sea=sea
application/x-sh=sh
application/x-shar=shar
application/x-shockwave-flash=swf
application/x-silverlight-app=xap
application/x-sql=sql
application/x-stuffit=sit
application/x-stuffitx=sitx
application/x-subrip=srt
application/x-sv4cpio=sv4cpio
application/x-sv4crc=sv4crc
application/x-t3vm-image=t3
application/x-tads=gam
application/x-tar=tar
application/x-tcl=tcl,tk
application/x-tex=tex
application/x-tex-tfm=tfm
application/x-texinfo=texinfo,texi
application/x-tgif=obj
application/x-ustar=ustar
application/x-virtualbox-hdd=hdd
application/x-virtualbox-ova=ova
application/x-virtualbox-ovf=ovf
application/x-virtualbox-vbox=vbox
application/x-virtualbox-vbox-extpack=vbox-extpack
application/x-virtualbox-vdi=vdi
application/x-virtualbox-vhd=vhd
application/x-virtualbox-vmdk=vmdk
application/x-wais-source=src
application/x-web-app-manifest+json=webapp
application/x-x509-ca-cert=der,crt,pem
application/x-xfig=fig
application/x-xliff+xml=xlf
application/x-xpinstall=xpi
application/x-xz=xz
application/x-zmachine=z1,z2,z3,z4,z5,z6,z7,z8
application/xaml+xml=xaml
application/xcap-att+xml=xav
application/xcap-caps+xml=xca
application/xcap-diff+xml=xdf
application/xcap-el+xml=xel
application/xcap-ns+xml=xns
application/xenc+xml=xenc
application/xhtml+xml=xhtml,xht
application/xliff+xml=xlf
application/xml=xml,xsl,xsd,rng
application/xml-dtd=dtd
application/xop+xml=xop
application/xproc+xml=xpl
application/xslt+xml=xsl,xslt
application/xspf+xml=xspf
application/xv+xml=mxml,xhvml,xvml,xvm
application/yang=yang
application/yin+xml=yin
application/zip=zip
audio/3gpp=3gpp
audio/adpcm=adp
audio/amr=amr
audio/basic=au,snd
audio/midi=mid,midi,kar,rmi
audio/mobile-xmf=mxmf
audio/mp3=mp3
audio/mp4=m4a,mp4a
audio/mpeg=mpga,mp2,mp2a,mp3,m2a,m3a
audio/ogg=oga,ogg,spx,opus
audio/s3m=s3m
audio/silk=sil
audio/vnd.dece.audio=uva,uvva
audio/vnd.digital-winds=eol
audio/vnd.dra=dra
audio/vnd.dts=dts
audio/vnd.dts.hd=dtshd
audio/vnd.lucent.voice=lvp
audio/vnd.ms-playready.media.pya=pya
audio/vnd.nuera.ecelp4800=ecelp4800
audio/vnd.nuera.ecelp7470=ecelp7470
audio/vnd.nuera.ecelp9600=ecelp9600
audio/vnd.rip=rip
audio/wav=wav
audio/wave=wav
audio/webm=weba
audio/x-aac=aac
audio/x-aiff=aif,aiff,aifc
audio/x-caf=caf
audio/x-flac=flac
audio/x-m4a=m4a
audio/x-matroska=mka
audio/x-mpegurl=m3u
audio/x-ms-wax=wax
audio/x-ms-wma=wma
audio/x-pn-realaudio=ram,ra
audio/x-pn-realaudio-plugin=rmp
audio/x-realaudio=ra
audio/x-wav=wav
audio/xm=xm
chemical/x-cdx=cdx
chemical/x-cif=cif
chemical/x-cmdf=cmdf
chemical/x-cml=cml
chemical/x-csml=csml
chemical/x-xyz=xyz
font/collection=ttc
font/otf=otf
font/ttf=ttf
font/woff=woff
font/woff2=woff2
image/aces=exr
image/apng=apng
image/avci=avci
image/avcs=avcs
image/avif=avif
image/bmp=bmp
image/cgm=cgm
image/dicom-rle=drle
image/emf=emf
image/fits=fits
image/g3fax=g3
image/gif=gif
image/heic=heic
image/heic-sequence=heics
image/heif=heif
image/heif-sequence=heifs
image/hej2k=hej2
image/hsj2=hsj2
image/ief=ief
image/jls=jls
image/jp2=jp2,jpg2
image/jpeg=jpeg,jpg,jpe
image/jph=jph
image/jphc=jhc
image/jpm=jpm
image/jpx=jpx,jpf
image/jxr=jxr
image/jxra=jxra
image/jxrs=jxrs
image/jxs=jxs
image/jxsc=jxsc
image/jxsi=jxsi
image/jxss=jxss
image/ktx=ktx
image/ktx2=ktx2
image/png=png
image/prs.btif=btif
image/prs.pti=pti
image/sgi=sgi
image/svg+xml=svg,svgz
image/t38=t38
image/tiff=tif,tiff
image/tiff-fx=tfx
image/vnd.adobe.photoshop=psd
image/vnd.airzip.accelerator.azv=azv
image/vnd.dece.graphic=uvi,uvvi,uvg,uvvg
image/vnd.djvu=djvu,djv
image/vnd.dvb.subtitle=sub
image/vnd.dwg=dwg
image/vnd.dxf=dxf
image/vnd.fastbidsheet=fbs
image/vnd.fpx=fpx
image/vnd.fst=fst
image/vnd.fujixerox.edmics-mmr=mmr
image/vnd.fujixerox.edmics-rlc=rlc
image/vnd.microsoft.icon=ico
image/vnd.ms-dds=dds
image/vnd.ms-modi=mdi
image/vnd.ms-photo=wdp
image/vnd.net-fpx=npx
image/vnd.pco.b16=b16
image/vnd.tencent.tap=tap
image/vnd.valve.source.texture=vtf
image/vnd.wap.wbmp=wbmp
image/vnd.xiff=xif
image/vnd.zbrush.pcx=pcx
image/webp=webp
image/wmf=wmf
image/x-3ds=3ds
image/x-cmu-raster=ras
image/x-cmx=cmx
image/x-freehand=fh,fhc,fh4,fh5,fh7
image/x-icon=ico
image/x-jng=jng
image/x-mrsid-image=sid
image/x-ms-bmp=bmp
image/x-pcx=pcx
image/x-pict=pic,pct
image/x-portable-anymap=pnm
image/x-portable-bitmap=pbm
image/x-portable-graymap=pgm
image/x-portable-pixmap=ppm
image/x-rgb=rgb
image/x-tga=tga
image/x-xbitmap=xbm
image/x-xpixmap=xpm
image/x-xwindowdump=xwd
message/disposition-notification=    "extensions": [
message/global=u8msg
message/global-delivery-status=u8dsn
message/global-disposition-notification=u8mdn
message/global-headers=u8hdr
message/rfc822=eml,mime
message/vnd.wfa.wsc=wsc
model/3mf=3mf
model/gltf+json=gltf
model/gltf-binary=glb
model/iges=igs,iges
model/mesh=msh,mesh,silo
model/mtl=mtl
model/obj=obj
model/step+xml=stpx
model/step+zip=stpz
model/step-xml+zip=stpxz
model/stl=stl
model/vnd.collada+xml=dae
model/vnd.dwf=dwf
model/vnd.gdl=gdl
model/vnd.gtw=gtw
model/vnd.mts=mts
model/vnd.opengex=ogex
model/vnd.parasolid.transmit.binary=x_b
model/vnd.parasolid.transmit.text=x_t
model/vnd.sap.vds=vds
model/vnd.usdz+zip=usdz
model/vnd.valve.source.compiled-map=bsp
model/vnd.vtu=vtu
model/vrml=wrl,vrml
model/x3d+binary=x3db,x3dbz
model/x3d+fastinfoset=x3db
model/x3d+vrml=x3dv,x3dvz
model/x3d+xml=x3d,x3dz
model/x3d-vrml=x3dv
text/cache-manifest=appcache,manifest
text/calendar=ics,ifb
text/coffeescript=coffee,litcoffee
text/css=css
text/csv=csv
text/html=html,htm,shtml
text/jade=jade
text/jsx=jsx
text/less=less
text/markdown=markdown,md
text/mathml=mml
text/mdx=mdx
text/n3=n3
text/plain=txt,text,conf,def,list,log,in,ini
text/prs.lines.tag=dsc
text/richtext=rtx
text/rtf=rtf
text/sgml=sgml,sgm
text/shex=shex
text/slim=slim,slm
text/spdx=spdx
text/stylus=stylus,styl
text/tab-separated-values=tsv
text/troff=t,tr,roff,man,me,ms
text/turtle=ttl
text/uri-list=uri,uris,urls
text/vcard=vcard
text/vnd.curl=curl
text/vnd.curl.dcurl=dcurl
text/vnd.curl.mcurl=mcurl
text/vnd.curl.scurl=scurl
text/vnd.dvb.subtitle=sub
text/vnd.familysearch.gedcom=ged
text/vnd.fly=fly
text/vnd.fmi.flexstor=flx
text/vnd.graphviz=gv
text/vnd.in3d.3dml=3dml
text/vnd.in3d.spot=spot
text/vnd.sun.j2me.app-descriptor=jad
text/vnd.wap.wml=wml
text/vnd.wap.wmlscript=wmls
text/vtt=vtt
text/x-asm=s,asm
text/x-c=c,cc,cxx,cpp,h,hh,dic
text/x-component=htc
text/x-fortran=f,for,f77,f90
text/x-handlebars-template=hbs
text/x-java-source=java
text/x-lua=lua
text/x-markdown=mkd
text/x-nfo=nfo
text/x-opml=opml
text/x-org=org
text/x-pascal=p,pas
text/x-processing=pde
text/x-sass=sass
text/x-scss=scss
text/x-setext=etx
text/x-sfv=sfv
text/x-suse-ymp=ymp
text/x-uuencode=uu
text/x-vcalendar=vcs
text/x-vcard=vcf
text/xml=xml
text/yaml=yaml,yml
video/3gpp=3gp,3gpp
video/3gpp2=3g2
video/h261=h261
video/h263=h263
video/h264=h264
video/iso.segment=m4s
video/jpeg=jpgv
video/jpm=jpm,jpgm
video/mj2=mj2,mjp2
video/mp2t=ts
video/mp4=mp4,mp4v,mpg4
video/mpeg=mpeg,mpg,mpe,m1v,m2v
video/ogg=ogv
video/quicktime=qt,mov
video/vnd.dece.hd=uvh,uvvh
video/vnd.dece.mobile=uvm,uvvm
video/vnd.dece.pd=uvp,uvvp
video/vnd.dece.sd=uvs,uvvs
video/vnd.dece.video=uvv,uvvv
video/vnd.dvb.file=dvb
video/vnd.fvt=fvt
video/vnd.mpegurl=mxu,m4u
video/vnd.ms-playready.media.pyv=pyv
video/vnd.uvvu.mp4=uvu,uvvu
video/vnd.vivo=viv
video/webm=webm
video/x-f4v=f4v
video/x-fli=fli
video/x-flv=flv
video/x-m4v=m4v
video/x-matroska=mkv,mk3d,mks
video/x-mng=mng
video/x-ms-asf=asf,asx
video/x-ms-vob=vob
video/x-ms-wm=wm
video/x-ms-wmv=wmv
video/x-ms-wmx=wmx
video/x-ms-wvx=wvx
video/x-msvideo=avi
video/x-sgi-movie=movie
video/x-smv=smv
x-conference/x-cooltalk=ice'

# making a named pipe file if not already created, for sending responses
[ -p http_response ] || mkfifo http_response

keep_running=1

cleanup() {
    # this will gracefully stop the while loop
    keep_running=0

    # finding the netcat process and abruptly killing it, hence killing the server
    pkill -SIGTERM -fx "nc --listen --local-port=$port${addr:+ $addr}"

    # removing the named pipe from the file system
    rm -f http_response
    
    [ $stay_quiet -eq 0 ] && echo -e "\r   \nKeyboard interrupt received, stopping the server."
    exit 0
}

# listening for bash termination signals (SIGINT & SIGTERM), so as to make sure to `cleanup` before terminating the program
trap cleanup SIGINT SIGTERM

# start the server indefinitely unless termination signals are trapped
while [ $keep_running -eq 1 ]
do
    cat http_response | nc --listen --local-port=$port $addr | request_handler
done