
#useful bash script to handle large pcaps
while read ATTACKIP; do
    tcpdump -n -r /media/sf_D_FOO/APR13_host60d69_04122338_04130303.pcap -w "/media/sf_D_FOO/$ATTACKIP.pcap" "host $ATTACKIP"
done < slicedIPs.txt

#useful tcpdump commands commands
  tcpprof -r /media/sf_D_FOO/APR13_host60d69_04122338_04130303.pcap -Sa > stats.txt

  tcpdump -nn -r /media/sf_D_FOO/APR13_host60d69_04122338_04130303.pcap 'tcp or udp' | cut -f 3 -d " " | cut -f 1-4 -d "." | sort | uniq > sourceIPs.txt

  tcpdump -nn -r /media/sf_D_FOO/APR13_host60d69_04122338_04130303.pcap 'tcp or udp' | cut -f 5 -d " " | cut -f 1-4 -d "." | sort | uniq > dstIPs.txt


#mergecap!
mergecap -a snort.log.* -w "04-13_0150_10_1_60_69_CON.pcap"
