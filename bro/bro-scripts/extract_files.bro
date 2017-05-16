@load base/frameworks/files

# The MIME headers that I believe might contain malicious files
global ext_map: table[string] of string = {

	["application/x-dosexec"] = "exe",
	["application/octet-stream"] = "bin",
	["application/java-archive"] = "jar",
	["application/x-sh"] = "sh",
	["application/vnd.ms-excel"] = "xls",
	["application/zip"] = "zip",
	["application/x-7z-compressed"] = "7z",
	["application/msword"] = "doc",
	["text/csv"] = "csv",
	["application/vnd.ms-powerpoint"]= "ppt"
	# Default is to ignore file
} &default = "";

#Input: File w/ metadata 
#Output: Certain files are saved if they are of interest (defined above) 
event file_sniff(f: fa_file, meta: fa_metadata) {
	local ext = "";
	if (meta?$mime_type)   {
		if (meta$mime_type in ext_map) {
			ext = ext_map[meta$mime_type];
			# Filename contains information about file such as which log entry it comes from and which host sent it
			local fname = fmt("%s-%s.%s", f$source, f$id, ext);
			# Print alert to stdout
			print fmt("%s captured: %s", ext, fname);
			# Save file to current directory
			Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
		}
	}
}
