# Each Bro script must be a unique module, which can be imported into other Bro scripts
module HTTPBeacon;

# These are modules included in Bro for parsing HTTP logs
@load policy/protocols/http/header-names
@load base/protocols/http

# These data structures can be accessed by any other script if you import the HTTPBeacon module
export {
    # Names the Bro log for this module LOG (standard practice)
    redef enum Log::ID += { LOG };
    
    # Custom data structure to store abnormal HTTP event information
    type abnormalHttpRecord: record {
        # Unique ID for each type of abnormal event
        event_id: count &log &optional;
        # Unique name that directly maps to event_id
        event_name: string &log &optional;
        # The artifact that caused the abnormality
        # such as base64 URL query or long hexadecimal subdomain
        event_artifact: string &log &optional;
    };

    # Custom data structure to store metadata about abnormal HTTP event information
    type Info: record {
        ts: time &log;
        local_host: addr &log;
        remote_host: addr &log;
        abnormal: abnormalHttpRecord &log &optional;
    };

    # Redefines the default HTTP log to append abnormal event information
    # if such information exists
    redef record HTTP::Info += {
        abnormal: abnormalHttpRecord &log &optional;
    };

}

# Whitelist domains, based on benign or already blocked domains
global whitelist_domains: set[string] = {"arpa", "bluenet", "mlg"};

# Base64 must be at least length 8 (or 7 with an equal or 6 with two equals)
global base64Pattern = /([a-zA-Z0-9+\/]{4})+([A-Za-z0-9+\/]{4}|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{2}==)$/; # Magic to detect base64...
# Detects ?id=akakb381jghs82==
global base64_query_pattern = /\?([a-zA-Z])+=([a-zA-Z0-9+\/]{4})+([A-Za-z0-9+\/]{4}|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{2}==)$/;# ?(key)=(base64value)

# Input: Vector of subdomains
# Output: True/False indicating whether the subdomain is a base64 subdomain
# * See base64Pattern regexp definition for what qualifies *
function base64_subdomain(subdomains: vector of string): bool {
    for(k in subdomains) {
        local subdomain = cat(subdomains[k]);
        local patternMatchResult = match_pattern(subdomain, base64Pattern);
        if (patternMatchResult$matched) {
            return T;
        }
    }
    return F;
}

# Input: Vector of subdomains
# Output: True/False indicating whether any of the subdomains are whitelisted
function whitelist_domain_check(subdomains: vector of string): bool {
    for(i in subdomains) {
        local subdomain_string = cat(subdomains[i]);
        if(subdomain_string in whitelist_domains) {
            return T;
        }
    }
    return F;
}

# Input: HTTP Reply information
# Output : Log entries optionally containing abnormal event information 
# Read Bro documentation for what fields are in connection record
event http_reply(c:connection, version:string, code:count, reason:string) {
    local ts = c$start_time;
    local host = c$id$orig_h;
    local server = c$id$resp_h;
    # If there is a host entry in the connection record
    if (c$http?$host) {
        local subdomains = split_string(c$http$host, /\./);
        # Check to make sure none of the subdomains are whitelisted
        if (!whitelist_domain_check(subdomains)) {
        # Event ID 12 - HIGH NUMBER OF SUBDOMAINS
            local domain_not_ip_check = match_pattern(subdomains[|subdomains|-1], /[a-zA-Z]+/);
            # If more than three subdomains and check to make sure it is a domain, not an IP address
            if (|subdomains| > 3 && domain_not_ip_check$matched){
                local subdomain_event_id = 12;
                local subdomain_event_name = "High number of subdomains";
                local subdomain_event_artifact = c$http$host;
                # Creates abnormalHTTPRecord
                local subdomain_abnormalrecordinfo: HTTPBeacon::abnormalHttpRecord = [$event_id=subdomain_event_id, $event_name=subdomain_event_name, $event_artifact=subdomain_event_artifact];
                # Creates abnormalInfo record
                local subdomain_httprecordinfo: HTTPBeacon::Info = [$ts=ts, $local_host=host, $remote_host=server, $abnormal=subdomain_abnormalrecordinfo];
                # Writes log entry to our custom abnormal_http.log file
                Log::write(HTTPBeacon::LOG, subdomain_httprecordinfo);
                # Appends abnormalHTTPRecord to standard HTTP log entry
                c$http$abnormal = subdomain_abnormalrecordinfo;
            }
        }
    }
}

# Input: HTTP Request information
# Output : Log entries optionally containing abnormal event information
# Read Bro documentation for what fields exist in connection record
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
    local ts = c$start_time;
    local host = c$id$orig_h;
    local server = c$id$resp_h;
    local base64_uri_query = find_last(unescaped_URI, base64_query_pattern);

    #EVENT ID 09 - BASE64 QUERY STRING
    # If the previous regexp search found a match
    if (base64_uri_query != "") {
        local base64query_event_id = 09;
        local base64query_event_name = "Base64 query string";
        local base64query_event_artifact = unescaped_URI;
        # Creates abnormalHTTPRecord
        local base64query_abnormalrecordinfo: HTTPBeacon::abnormalHttpRecord = [$event_id=base64query_event_id, $event_name=base64query_event_name, $event_artifact=base64query_event_artifact];
        # Creates abnormalHTTP Info record
        local base64query_httprecordinfo: HTTPBeacon::Info = [$ts=ts, $local_host=host, $remote_host=server, $abnormal=base64query_abnormalrecordinfo];
        # Writes abnormalHTTP record to custom log file
        Log::write(HTTPBeacon::LOG, base64query_httprecordinfo);
        # Appends abnormalHTTP record to standar HTTP log entry
        c$http$abnormal = base64query_abnormalrecordinfo;
    }
}

# Initializes Bro script to write log entries to abnormal_http.log file
event bro_init() {
    Log::create_stream(HTTPBeacon::LOG, [$columns=Info, $path="abnormal_http"]);
}
