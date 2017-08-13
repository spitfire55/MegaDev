# Each Bro script must have a unique module name in order to be imported into other Bro scripts
module DNSBeacon;

# Imported module from Bro containing data structures used in DNS logs
@load base/protocols/dns

# These data structures can be referenced if this script is imported into another script
export {
    # Standard definition of custom log
    redef enum Log::ID += { LOG };
    
    # Custom data structure to store abnormal DNS event information
    type abnormalDnsRecord: record {
        # Unique ID for each type of abnormal event
        event_id: count &log &optional;
        # Unique name that directly maps to event_id
        event_name: string &log &optional;
        # The artifact that causes the abnormality
        # such as base64 string or reserved subnet in reply
        event_artifact: string &log &optional;
    };

    # Custom data structure to store metadata about abnormal DNS event
    type Info: record {
        ts: time &log;
        local_host: addr &log;
        remote_host: addr &log;
        abnormal: abnormalDnsRecord &log &optional;
    };

    # Redefines default DNS log entry to optionally append abnormal information if it exists
    redef record DNS::Info += {
        abnormal: abnormalDnsRecord &log &optional;
    };

}

# Whitelist of known benign subdomains or already blocked subdomains
global whitelist_domains: set[string] = {"naples", "arpa", "bluenet", "ssg"};

#Reference: https://en.wikipedia.org/wiki/Reserved_IP_addresses
# 10.0.0.0/8 and removed b/c local traffic = many false positives
global set_reserved_ipv4_subnets: set[subnet] = {0.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24,
192.88.99.0/24, 192.168.0.0/16, 192.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4, 255.255.255.255/32};

global reserved_ipv4_subnets = [0.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24,
192.88.99.0/24, 192.168.0.0/16, 192.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4, 255.255.255.255/32];
# fd00 removed b/c local traffic = many false positives
global reserved_ipv6_subnets = [[::1]/128, [::ffff:0:0]/96, [100::]/64, [64:ff9b::]/96, [2001::]/30, [2001:10::]/28, [2001:20::]/28, [2001:db8::]/32, [2002::]/16,
[fc00::]/8, [fe80::]/10, [ff00::]/8];

global dn_record_store: table[string] of set[addr];

# Standard procedure to initialize custom log names abnormal_dns.log
event bro_init()
{
    Log::create_stream(DNSBeacon::LOG, [$columns=Info, $path="abnormal_dns"]);
}

#Input: addr
#Output: subnet that corrosponds to the classiful network id
function get_class_network(a: addr): subnet {
	if(a < 128.0.0.0){ #Class A
		return a/8;
	}
	else if(a < 192.0.0.0){ #Class B
		if(a < 172.16.0.0 || a > 172.32.0.0) return a/16;
		else return a/12;
	}	
	else if(a < 224.0.0.0){
		if(a > 192.18.0.0 && a < 192.19.0.0) return a/15;
		else if(a > 192.168.0.0 && a < 192.169.0.0) return a/16;
		else return a/24; #Class C
	}
	else if(a < 240.0.0.0){ #Class D
		return a/4;
	}
	else if(a < 255.255.255.255){ #Class E
		return a/4;
	}
	else return a/32; #255.255.255.255
}

# Input: Vector of subdomains
# Output : True/False which indicates whether one of the subdomains is only 4 or more hexadecimal characters 
function check_hex_only_subdomain(subdomains: vector of string): bool {
    for (d in subdomains) {
        local subdomain = subdomains[d];
        # Check to see if subdomain is just three or more hex characters
        local patternMatchResult = match_pattern(subdomain, /[a-fA-F0-9]{4,}$/);
        if (patternMatchResult$matched) {
            return T;
        }
    }
    return F;
}

# Input: Vector of subdomains
# Output: True/False which indicates whether one of the subdomains is whitelisted
function whitelist_domain_check(subdomains: vector of string): bool {
    for(i in subdomains) {
        local subdomain_string = cat(subdomains[i]);
        if(subdomain_string in whitelist_domains) {
            return T;
        }
    }
    return F;
}

#Input: string representing domain name
#Output: the top three subdomains i.e. the root and two subdomains under it
#NOTE: will return 2 or less subdomains if the argument is less than 
#three subdomains 
function get_top_domains(dn: string): string {
	local dn_vector = split_string(dn, /\./);
	local ans = "";
	local index = |dn_vector|-1;
	local cnt = 0;
	while(index > 0 && cnt < 3){
		ans = dn_vector[index]+"."+ans;
		index-=1;
		cnt+=1;	
	}
	#TODO print fmt("%s", dn);
	#print fmt("%s", ans);
	return ans;
}

function push_ab_dns_log(c: connection, a_rsv_evnt_id: count, a_rsv_evnt_name: string, a: addr){
	    local a_rsv_abnormalrecordinfo: DNSBeacon::abnormalDnsRecord = [$event_id = a_rsv_evnt_id, $event_name = a_rsv_evnt_name, $event_artifact = fmt("%s", a)];
            local a_rsv_dnsrecordinfo: DNSBeacon::Info = [$ts=c$start_time, $local_host=c$id$orig_h, $remote_host=c$id$resp_h, $abnormal=a_rsv_abnormalrecordinfo];
            Log::write(DNSBeacon::LOG, a_rsv_dnsrecordinfo);
            c$dns$abnormal = a_rsv_abnormalrecordinfo;
} 

# DNS Request - Event IDs 40 to 59
# Input: DNS Request information
# Output: Log entries that indicate one (or more) of the following abnormal signatures was found:
#   - High number of subdomains
#   - Hexadecimal subdomain
event dns_request(c: connection, msg:dns_msg, query: string, qtype: count, qclass: count) {
    local ts = c$start_time;
    local host = c$id$orig_h;
    local server = c$id$resp_h;
    local event_id = 40;
    local subdomains = split_string(query, /\./);
    local whitelisted = whitelist_domain_check(subdomains);

    # EVENT ID 45 - HIGH NUMBER OF SUBDOMAINS
    if ((|subdomains| > 4) && ! whitelisted) {
        local subdomain_event_id = event_id + 5;
        local subdomain_event_name = "High Number of Subdomains";
        # Reconstructs the subdomains to remove subdomains (i.e. foo.bar.xyz.cnn.org -> xyz.cnn.org )
        local base_domain = cat_sep(".", "", subdomains[|subdomains|-3], subdomains[|subdomains|-2], subdomains[|subdomains|-1]);
        # Create abnormalDNSRecord 
        local subdomains_abnormalrecordinfo: DNSBeacon::abnormalDnsRecord = [$event_id=subdomain_event_id, $event_name=subdomain_event_name, $event_artifact=query];
        # Creates abnormalInfo record
        local subdomains_dnsrecordinfo: DNSBeacon::Info = [$ts=ts, $local_host=host, $remote_host=server, $abnormal=subdomains_abnormalrecordinfo];
        # Write abnormalDNS record to its own log file
        Log::write(DNSBeacon::LOG, subdomains_dnsrecordinfo);
        # Append abnormalDNS record to standard DNS log file
        c$dns$abnormal = subdomains_abnormalrecordinfo;
    }
       
    # EVENT ID 50 - HEXADECIMAL SUBDOMAIN
    if (check_hex_only_subdomain(subdomains) && ! whitelisted) {
        local hexdomain_event_id = event_id + 10;
        local hexdomain_event_name = "Hexadecimal Subdomain";
        # Creates abnormalDNSRecord
        local hexdomain_abnormalrecordinfo: DNSBeacon::abnormalDnsRecord = [$event_id=hexdomain_event_id, $event_name = hexdomain_event_name, $event_artifact=query];
        # Creates abnormalInfo record
        local hexdomain_dnsrecordinfo: DNSBeacon::Info = [$ts=ts, $local_host=host, $remote_host=server, $abnormal=hexdomain_abnormalrecordinfo];
        # Writes abnormalDNS record to its own log file
        Log::write(DNSBeacon::LOG, hexdomain_dnsrecordinfo);
        # Append abnormalDNS record to standard DNS log file
        c$dns$abnormal = hexdomain_abnormalrecordinfo;
    }
}

# EVENT ID 55 - A RECORD REPLY RESERVED IP ADDRESS
# Detects whether the IPv4 address is in reserved subnet
event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr) {
    if(get_class_network(a) in set_reserved_ipv4_subnets) push_ab_dns_log(c,55,"A Record Reply Reserved IP Address",a); 
    local top = get_top_domains(ans$query);
    if(top in dn_record_store){
    	local top_set = dn_record_store[top]; 
	add top_set[a]; #TODO check mutablity issues
	if( |top_set| > 9) push_ab_dns_log(c, 57, fmt("A Record Reply that maps too many (%s) IPs to a subdomain", |top_set|),a);
	dn_record_store[top]=top_set;     
	}
    else{
	dn_record_store[top] = set(a);	    
    }
    #print "======================================";
    #for(rec in dn_record_store) {
    	#print rec, dn_record_store[rec];
	#if (dn_record_store[i,j] == "done") break;
    	#if (dn_record_store[i,j] == "skip") next;
    	#print i,j;
	#}
}


# EVENT ID 65 - AAAA RECORD REPLY RESERVED IP ADDRESS
# Detects whether the IPv6 address is in reserved subnet
event dns_AAAA_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr) {
    local ts = c$start_time;
    local host = c$id$orig_h;
    local server = c$id$resp_h;
    local aaaa_reserved_event_id = 65;
    local aaaa_reserved_event_name = "AAAA Record Reply Reserved IP Address";
    #TODO: Create IPv6 array of reserved CIDRs
    for (cidr in reserved_ipv6_subnets) {
    #TODO Get rid of this naive iteration for an more efficent lookup
    #i.e. transform a into network id; hah table lookup 
    #TODO Make into a function call    
    if (a in cidr) {
            local aaaa_reserved_abnormalrecordinfo: DNSBeacon::abnormalDnsRecord = [$event_id = aaaa_reserved_event_id, $event_name = aaaa_reserved_event_name, $event_artifact = fmt("%s", a)];
            local aaaa_reserved_dnsrecordinfo: DNSBeacon::Info = [$ts=ts, $local_host=host, $remote_host=server, $abnormal=aaaa_reserved_abnormalrecordinfo];
            Log::write(DNSBeacon::LOG, aaaa_reserved_dnsrecordinfo);
            c$dns$abnormal = aaaa_reserved_abnormalrecordinfo;
        }
    }
}
