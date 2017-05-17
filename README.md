# Network Monitoring and Logging Capstone

**Authors**: Mitchell DeRidder, Dale Lakes, Matthew Shockley

**Advisors**: [MAJ Klimkowski](code@benklim.org), MAJ Petullo

This repo will contain our team's code for our CS401 capstone project.

ELK Installation Guide for CentOS 7: 
https://www.digitalocean.com/community/tutorials/how-to-install-elasticsearch-logstash-and-kibana-elk-stack-on-centos-7
 
![ELK STACK](https://assets.digitalocean.com/articles/elk/elk-infrastructure.png)

* Logstash: The server component of Logstash that processes incoming logs

* Elasticsearch: Stores all of the logs

* Kibana: Web interface for searching and visualizing logs, which will be proxied through Nginx

* Filebeat: Installed on client servers that will send their logs to Logstash, Filebeat serves as a log shipping agent that utilizes the lumberjack networking protocol to communicate with Logstash

* Bro: Network Intrusion Detection System, used for capturing live network traffic and detecting anomalous traffic with custom heuristics, based upon CDX '16 traffic and Cobalt Strike packet captures.
	* See [the wiki](https://github.com/spitfire55/MegaDev_Capstone/wiki/Abnormal-Logging-Identifiers) for for more information about our custom anomalous signatures and heuristics
