<pre>
# paloalto-parse_fw_traffic
Perl script to parse Palo Alto Networks firewall traffic logs and filter records and output statistics

Usage: parse_fw_traffic [OPTIONS] [FILE]...
Parses records from a PaloAlto traffic logfile and outputs top results by
hosts.

  [FILE]  Log files may be specified on the command line or records may be
          piped in.  Files ending in ".gz" will be decompressed when read.

  --fw=FWNAME              Only process records for firewall named
  --rule=RULE              Only process records contains RULE
  --srczone=SONE           Only process records from zone
  --dstzone=SONE           Only process records to zone
  --src=ip                 Limit to source IP
  --dst=ip                 Limit to destination IP
  --since=datetime         Only consider records since datetime
  --before=datetime        Only consider records before datetime
  -c10              Number of records to output for each category.
                           Use (-c) for all records.
  -?, --help, --usage      Outputs program usage.

  -s                       Output only source IPs
  -d                       Output only destination IPs
  --deny                   Outout only sessions that are blocked
  --flows                  Output individual flows
  --ports                  Categorize by ports
  -l                       Output log lines
  -f                       Output records added to file in real time (follow)
                             Gives periodic reports.
                             Uses: tail -f [FILE] | /usr/local/sbin/parse_fw_traffic
  -p10                     Periodic report interval (secs)
</pre>
