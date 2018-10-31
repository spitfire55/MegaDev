# Network Monitoring and Logging Capstone

**Authors**: Mitchell DeRidder, Dale Lakes, Matthew Shockley

**Advisors**: [MAJ Benjamin Klimkowski](www.benklim.org), [LTC W. Michael Petullo](flyn.org)

This repo will contain our team's code for our undergraduate design capstone, where we used Bro to successfully detect malicious traffic from compromised machines to a remote command and control (C2) server. Specifically, our team focused on detecting Cobalt Strike, a popular penetration tool. Cobalt Strike possesses a sophisticated callback mechanism that uses common protocols to beacon back to a remote C2 server and fetch instructions. From the remote server, attackers can send C2 instructions to processes running on the compromised hosts. This stored-and-forward architecture is designed to avoid detection, blending in with ordinary traffic. 

Our techniques were evaluated during the 2017 Cyber Defense Exercise (CDX), where undergraduates compete against the Nation Security Agency (NSA) Red Team. Datasets, documentation and other information about the 2016 CDX and the 2017 CDX can be found at [flyn.org](https://flyn.org/). 

ELK Installation Guide for CentOS 7: 
https://www.digitalocean.com/community/tutorials/how-to-install-elasticsearch-logstash-and-kibana-elk-stack-on-centos-7
 
![ELK STACK](https://assets.digitalocean.com/articles/elk/elk-infrastructure.png)

* Logstash: The server component of Logstash that processes incoming logs

* Elasticsearch: Stores all of the logs

* Kibana: Web interface for searching and visualizing logs, which will be proxied through Nginx

* Filebeat: Installed on client servers that will send their logs to Logstash, Filebeat serves as a log shipping agent that utilizes the lumberjack networking protocol to communicate with Logstash

* Bro: Network Intrusion Detection System, used for capturing live network traffic and detecting anomalous traffic with custom heuristics, based upon CDX '16 traffic and Cobalt Strike packet captures.
	* See [the wiki](https://github.com/spitfire55/MegaDev_Capstone/wiki/Abnormal-Logging-Identifiers) for for more information about our custom anomalous signatures and heuristics
