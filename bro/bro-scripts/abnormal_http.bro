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
    
# A containter that keeps track of method counts
type Host_Rec: record{
	post_count:count;
	get_count: count;
	other_count: count;
 };

# A Map to get track of post/get state
global method_freq_map: table[addr] of Host_Rec;

# Whitelist domains, based on benign or already blocked domains
global whitelist_domains: set[string] = {"arpa", "bluenet", "mlg"};

# Whitelist of legal http methods
global legal_http_methods: set[string] = {"POST", "GET", "HEAD", "PUT", "DELETE", "OPTIONS", "CONNECT"};

# Whitelist IPs Set of ip's to ignore
global whitelist_ips: set[addr] = {10.1.60.2};
 
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

#Input: information to log
#Output: void function; put info in to log
#Helper function to handle logs
function push_ab_http_log(c: connection, evnt_id: count, evnt_name: string, art: string){
	# Creates abnormalHTTPRecord
	local abnormalrecordinfo: HTTPBeacon::abnormalHttpRecord = [$event_id=evnt_id, $event_name=evnt_name, $event_artifact=art];
	# Creates abnormalInfo record
	local httprecordinfo: HTTPBeacon::Info = [$ts=c$start_time, $local_host=c$id$orig_h, $remote_host=c$id$resp_h, $abnormal=abnormalrecordinfo];
	# Writes log entry to our custom abnormal_http.log file
	Log::write(HTTPBeacon::LOG, httprecordinfo);
	# Appends abnormalHTTPRecord to standard HTTP log entry
	c$http$abnormal = abnormalrecordinfo;
}


# Input: HTTP Reply information
# Output : Log entries optionally containing abnormal event information 
# Read Bro documentation for what fields are in connection record
event http_reply(c:connection, version:string, code:count, reason:string) {
    if (c$http?$host) {
        local subdomains = split_string(c$http$host, /\./);
        # Check to make sure none of the subdomains are whitelisted
        if (!whitelist_domain_check(subdomains)) {
        # Event ID 12 - HIGH NUMBER OF SUBDOMAINS
            local domain_not_ip_check = match_pattern(subdomains[|subdomains|-1], /[a-zA-Z]+/);
            # If more than three subdomains and check to make sure it is a domain, not an IP address
            if (|subdomains| > 3 && domain_not_ip_check$matched){
                push_ab_http_log(c, 12, "High number of subdomains", c$http$host);
            }
        }
    }
}

# Input: HTTP Request information
# Output : Log entries optionally containing abnormal event information
# Read Bro documentation for what fields exist in connection record
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
    local base64_uri_query = find_last(unescaped_URI, base64_query_pattern);
    #EVENT ID 09 - BASE64 QUERY STRING
    # If the previous regexp search found a match
    if (base64_uri_query != "") {
        push_ab_http_log(c, 9,"Base64 query string", unescaped_URI); 
    }
    #EVENT ID 08 - POST/GET ASYMMETRY
    local host_rec: Host_Rec;
    if(c$id$resp_h in method_freq_map) host_rec = method_freq_map[c$id$resp_h];
    else host_rec = Host_Rec($post_count = 0, $get_count = 0, $other_count=0);
    if(method == "POST") host_rec$post_count += 1;
    else if(method == "GET") host_rec$get_count += 1;
    else{
	host_rec$other_count+=1;
     	#EVENT ID 07 - Unknown_HTTP_method
	if( method !in legal_http_methods) 
		push_ab_http_log(c, 7, "Illegal Http Method", unescaped_URI+" "+method);	
	}
    if( host_rec$post_count > 0 && (host_rec$get_count / (host_rec$post_count*1.0)) > 20){
		local tot_count = host_rec$post_count + host_rec$get_count;
		if( c$id$resp_h !in whitelist_ips && (tot_count < 100 || tot_count % 100 == 0))
			push_ab_http_log(c, 8, "POST/GET ASYMMETRY", unescaped_URI+" "+fmt("post's: %s",host_rec$post_count)+" "+fmt("get's: %s",host_rec$get_count));	
	}
    method_freq_map[c$id$resp_h] = host_rec;
    
}


# Initializes Bro script to write log entries to abnormal_http.log file
event bro_init() {
    Log::create_stream(HTTPBeacon::LOG, [$columns=Info, $path="abnormal_http"]);
}
