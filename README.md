<pre>
# paloalto-parse_fw_traffic
Usage: parse_fw_traffic [OPTIONS] [FILE]...
Parses records from a PaloAlto traffic logfile and outputs top results by
hosts.

  [FILE]  Log files may be specified on the command line or records may be
          piped in.  Files ending in ".gz", ".bz", or ".bz2" will be
          decompressed when read.  Use -l -c0 to output raw records.

   --fw=FWNAME              Only process records for firewall named
  --rule=RULE              Only process records that contains RULE
  --proto=tcp              Only process records for protocol
  --srczone=ZONE           Only process records from zone
  --dstzone=ZONE           Only process records to zone
  --src=ip                 Limit to source IP
  --dst=ip                 Limit to destination IP
  --since=datetime         Only consider records since datetime
  --before=datetime        Only consider records before datetime
  -c10                     Number of records to output for each category.
                           Use (-c) for all records.  Use (-c0) for no summary.
  -s                       Output only source IPs
  -d                       Output only destination IPs
  --deny                   Output only sessions that are blocked
  --flows                  Output individual flows
  --ports                  Categorize by ports
  -l                       Output log lines
  -L                       Pretty print log lines
  -f                       Output records added to file in real time (follow)
                             Gives periodic reports.
                             Uses: tail -f [FILE] | ./parse_fw_traffic
  -p10                     Periodic report interval (secs)
  -?, --help, --usage      Outputs program usage.

# paloalto-parse_fw_gp
Usage: parse_fw_gp [OPTIONS] [FILE]...
Parses records from a PaloAlto GlobalProtect logfile

  [FILE]  Log files may be specified on the command line or records may be
          piped in.  Files ending in ".gz", ".bz", or ".bz2" will be
          decompressed when read.  Use -l -c0 to output raw records.

  -S                       Only success records
  -F                       Only failure records
  --fw=FWNAME              Only records for firewall named
  --vpn=VPNNAME            Only records for VPN named
  --user=username          Only records for username
  --wsname=name            Only records for workstation
  --public=ip              Limit to public IP
  --private=ip             Limit to priate IP
  --since=datetime         Only consider records since datetime
  --before=datetime        Only consider records before datetime
  --foreign                Only non-US records
  --satellite              Output LSVPN satellite records instead
  --portal                 Only portal records
  --gateway                Only gateway records
  --login                  Only login/logout/connected records
  -l                       Output log lines
  -L                       Pretty print log lines (default)
  -f                       Output records added to file in real time (follow)
                             Uses: tail -f [FILE] | $0
  -?, --help, --usage      Outputs program usage.

</pre>

