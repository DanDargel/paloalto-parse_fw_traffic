#!/usr/bin/perl
# Parse PaloAlto firewall traffic logs and
# display top results by hosts
#
# 2015-03-12  dargel(at)uwplatt.edu  Created
# 2022-03-24  dargel(at)uwplatt.edu  Add counters for rules
# 2022-04-07  dargel(at)uwplatt.edu  Add src/detzone, fw, deny, rule options and fix periodic
# 2022-04-07  dargel(at)uwplatt.edu  Added pretty print option

use strict;
use Date::Parse;

# Hashes to count totals for each field
my ($total, $total_src_bytes, $total_dst_bytes, %protos, %srcs, %dsts, %src_bytes, %dst_bytes, %sports, %dports, %bytes, %actions, %srclocs, %dstlocs, %flows, %rules);

# Defaults
my $maxcount = 10;
my $repinterval = 0;
my ($since, $before, $src_opt, $dst_opt, $srczone, $dstzone, $device, $rule_opt);

# Pretty print format
my $fmt = "%-19.19s %-10.10s %-10.10s %-5.5s %-10.10s %15.15s:%-5.5s %-15.15s %-10.10s %15.15s:%-5.5s %-15.15s %-15.15s %-20.20s %8.8s %8.8s\n";

# Parse command options
use Getopt::Long;
my %opts=();
Getopt::Long::Configure qw(bundling);
GetOptions(\%opts,
  "c:-1" => \$maxcount,
  "p:10" => \$repinterval,
  "since=s" => sub{$since=str2time($_[1])},
  "before=s" => sub{$before=str2time($_[1])},
  "src=s" => \$src_opt,
  "dst=s" => \$dst_opt,
  "srczone=s" =>\$srczone,
  "dstzone=s" =>\$dstzone,
  "rule=s" =>\$rule_opt,
  "s",
  "d",
  "deny",
  "flows",
  "ports",
  "fw=s" => \$device,
  "l",
  "L",
  "f",
  "help|usage|?" => \&usage) or usage();

my $all = not ($opts{s} or $opts{d});  # Output all categories

$ARGV[0] = '-' if (!$ARGV[0]);  # Stdio if no input file

# Subroutine to print usage
sub usage {
  print <<EOT;
Usage: $0 [OPTIONS] [FILE]...
Parses records from a PaloAlto traffic logfile and outputs top results by
hosts.

  [FILE]  Log files may be specified on the command line or records may be
          piped in.  Files ending in ".gz" will be decompressed when read.

  --fw=FWNAME              Only process records for firewall named
  --rule=RULE              Only process records contains RULE
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
  --deny                   Outout only sessions that are blocked
  --flows                  Output individual flows
  --ports                  Categorize by ports
  -l                       Output log lines
  -L                       Pretty print log lines
  -f                       Output records added to file in real time (follow)
                             Gives periodic reports.
                             Uses: tail -f [FILE] | $0
  -p10                     Periodic report interval (secs)
  -?, --help, --usage      Outputs program usage.

EOT
  exit;
}

# Output pretty print header
printf $fmt,'Time','Device','Action','Proto','SZone','Source','SPort','SCountry','DZone','Dest','DPort','DCountry','Application','Rule','Packets','Bytes' if ($opts{L});

#-------------------------------------------------------------------------------
# Mainline

$SIG{INT} = \&ctrlc;
$SIG{ALRM} = \&periodic;
$repinterval = 10 if ($opts{f} && $repinterval < 1);
alarm $repinterval if ($repinterval > 0);  # Do periodic reporting

# Parse each input file
parse_file($_) foreach (@ARGV);

output();
exit;

#-------------------------------------------------------------------------------
# Procedure to abort on control-c and output report
sub ctrlc {
  $SIG{INT} = 'DEFAULT';
  output();
  exit;
}

#-------------------------------------------------------------------------------
# Procedure to output a periodic report
sub periodic {
  alarm $repinterval;
  output();
  print "\n";
}

#-------------------------------------------------------------------------------
# Output results
sub output {
  return if ($maxcount == 0);  # Skip if output record count is zeor

  print "\n";
  print "Total log entries processed: $total\n";

    print "\n";
    printf "Actions: Total actions: %s\n", scalar keys(%actions);
    print "Count      Percent Type\n";
    print "---------- ------- ---------------\n";
    my $count = $maxcount;
    foreach (sort {$actions{$b} <=> $actions{$a}} keys(%actions)) {
      last if ($count-- == 0);
      printf "%10s %7.4f %s\n", $actions{$_}, $actions{$_}*100/$total, $_;
    }

    print "\n";
    printf "Rules: Total rules: %s\n", scalar keys(%rules);
    print "Count      Percent Type\n";
    print "---------- ------- ---------------\n";
    my $count = $maxcount;
    foreach (sort {$rules{$b} <=> $rules{$a}} keys(%rules)) {
      last if ($count-- == 0);
      printf "%10s %7.4f %s\n", $rules{$_}, $rules{$_}*100/$total, $_;
    }

    print "\n";
    printf "Protocols: Total protocols: %s\n", scalar keys(%protos);
    print "Count      Percent Protocol\n";
    print "---------- ------- ---------------\n";
    my $count = $maxcount;
    foreach (sort {$protos{$b} <=> $protos{$a}} keys(%protos)) {
      last if ($count-- == 0);
      printf "%10s %7.4f %s\n", $protos{$_}, $protos{$_}*100/$total, $_;
    }

  if ($opts{ports}) {
    print "\n";
    printf "Source Ports: Total ports: %s\n", scalar keys(%sports);
    print "Count      Percent IP Address\n";
    print "---------- ------- ---------------\n";
    my $count = $maxcount;
    foreach (sort {$sports{$b} <=> $sports{$a}} keys(%sports)) {
      last if ($count-- == 0);
      printf "%10s %7.4f %s\n", $sports{$_}, $sports{$_}*100/$total, $_;
    }
    print "\n";
    printf "Destination Ports: Total ports: %s\n", scalar keys(%dports);
    print "Count      Percent Protocol/Port\n";
    print "---------- ------- ---------------\n";
    my $count = $maxcount;
    foreach (sort {$dports{$b} <=> $dports{$a}} keys(%dports)) {
      last if ($count-- == 0);
      printf "%10s %7.4f %s\n", $dports{$_}, $dports{$_}*100/$total, $_;
    }
  }

  if ($opts{s} or $all) {
    print "\n";
    printf "Sources by Count: Total hosts: %s %sB\n", scalar keys(%srcs), scalenum($total_src_bytes);
    print "Count      Percent IP Address\n";
    print "---------- ------- ---------------\n";
    my $count = $maxcount;
    foreach (sort {$srcs{$b} <=> $srcs{$a}} keys(%srcs)) {
      last if ($count-- == 0);
      printf "%10s %7.4f %s %sB %7.4f\%\n", $srcs{$_}, $srcs{$_}*100/$total, $_, scalenum($src_bytes{$_}), eval{$src_bytes{$_}*100/$total_src_bytes};
    }
#    print "\n";
#    printf "Sources by IP: Total hosts: %s %sB\n", scalar keys(%srcs), scalenum($total_src_bytes);
#    print "Count      Percent IP Address\n";
#    print "---------- ------- ---------------\n";
#    my $count = $maxcount;
#    foreach (sort {ip2dec($a) <=> ip2dec($b)} keys(%srcs)) {
#      last if ($count-- == 0);
#      printf "%10s %7.4f %s %sB %7.4f\%\n", $srcs{$_}, $srcs{$_}*100/$total, $_, scalenum($src_bytes{$_}), eval{$src_bytes{$_}*100/$total_src_bytes};
#    }
    print "\n";
    printf "Source Countries: Total Countries: %s\n", scalar keys(%srclocs);
    print "Count      Percent IP Address\n";
    print "---------- ------- ---------------\n";
    my $count = $maxcount;
    foreach (sort {$srclocs{$b} <=> $srclocs{$a}} keys(%srclocs)) {
      last if ($count-- == 0);
      printf "%10s %7.4f %s\n", $srclocs{$_}, $srclocs{$_}*100/$total, $_;
    }
  }

  if ($opts{d} or $all) {
    print "\n";
    printf "Destinations: Total hosts: %s %sB\n", scalar keys(%dsts), scalenum($total_dst_bytes);
    print "Count      Percent IP Address\n";
    print "---------- ------- ---------------\n";
    my $count = $maxcount;
    foreach (sort {$dsts{$b} <=> $dsts{$a}} keys(%dsts)) {
      last if ($count-- == 0);
      printf "%10s %7.4f %s %sB %7.4f\%\n", $dsts{$_}, $dsts{$_}*100/$total, $_, scalenum($dst_bytes{$_}), eval{$dst_bytes{$_}*100/$total_dst_bytes};
    }
#    print "\n";
#    printf "Destinations by IP: Total hosts: %s %sB\n", scalar keys(%dsts), scalenum($total_dst_bytes);
#    print "Count      Percent IP Address\n";
#    print "---------- ------- ---------------\n";
#    my $count = $maxcount;
#    foreach (sort {ip2dec($a) <=> ip2dec($b)} keys(%dsts)) {
#      last if ($count-- == 0);
#      printf "%10s %7.4f %s %sB %7.4f\%\n", $dsts{$_}, $dsts{$_}*100/$total, $_, scalenum($dst_bytes{$_}), eval{$dst_bytes{$_}*100/$total_dst_bytes};
#    }
    print "\n";
    printf "Destination Countries: Total Countries: %s\n", scalar keys(%dstlocs);
    print "Count      Percent IP Address\n";
    print "---------- ------- ---------------\n";
    my $count = $maxcount;
    foreach (sort {$dstlocs{$b} <=> $dstlocs{$a}} keys(%dstlocs)) {
      last if ($count-- == 0);
      printf "%10s %7.4f %s\n", $dstlocs{$_}, $dstlocs{$_}*100/$total, $_;
    }
  }


  if ($opts{flows}) {
    print "\n";
    printf "Flows: Total flows: %s\n", scalar keys(%flows);
    print "Count      Percent Flow\n";
    print "---------- ------- ---------------\n";
    my $count = $maxcount;
    foreach (sort {$flows{$b} <=> $flows{$a}} keys(%flows)) {
      last if ($count-- == 0);
      printf "%10s %7.4f %s\n", $flows{$_}, $flows{$_}*100/$total, $_;
    }
  }


  # Reset counters
  %actions = ();
  %protos = ();
  %sports = ();
  %dports = ();
  %srcs = ();
  %dsts = ();
  %srclocs = ();
  %dstlocs = ();
  %src_bytes = ();
  %dst_bytes = ();
  %flows = ();
  %rules = ();
  $total = 0;
  $total_src_bytes = 0;
  $total_dst_bytes = 0;
}

#-------------------------------------------------------------------------------
# Parse the contents of a file
sub parse_file {
  my($inf) = @_;

  # Check if compressed and open file
  $inf =~ s/(.*\.gz)$/zcat $1|/;
  $inf =~ s/(.*\.bz)$/bzcat $1|/;
  $inf =~ s/(.*\.bz2)$/bzcat $1|/;
  $inf = "tail -0f $inf |" if ($opts{f});  # follow file
  open(INF, $inf) or die "can't open $inf: $!";

  # Parse records of the file
  while (<INF>) {
    chomp;
    parse_log_line($_);
  }
  close INF or die "bad stat: $! $?";
}

#-------------------------------------------------------------------------------
sub parse_log_line
{
  # Grab the line we were given
  my($line) = @_;

  # Parse the line
  my ($logheader, $receive_time, $serial, $type, $subtype, $f1, $time_generated, $src, $dst, $natsrc, $natdst, $rule, $srcuser, $dstuser, $app, $vsys, $from, $to, $inbound_if, $outbound_if, $logset, $d1, $sessionid, $repeatcnt, $sport, $dport, $natsport, $natdport, $flags, $proto, $action, $bytes, $bytes_sent, $bytes_received, $packets, $start, $elapsed, $category, $f2, $seqno, $actionflags, $srcloc, $dstloc, $f3, $pkts_sent, $pkts_received, $sessionend, $group1, $group2, $group3, $group4, $vsysname, $devname, $f4) = split(/,/,$line);
  $logheader =~ /^(\w+ [ \d]\d \d\d:\d\d:\d\d) ([^\s]+) (\d+)$/;
  my ($timestamp, $fw) = ($1, $2);

  # Only TRAFFIC logs
  return if ($type ne 'TRAFFIC');

  # Only a certain firewall
  return if ($device && $devname ne $device);

  # Only traffic that is not denied
  return if ($opts{deny} && $action eq 'allow');

  # Only traffic that contains rule_opt
  return if ($rule_opt && $rule !~ m/$rule_opt/i);

  # Check source and destination IP and zone
  return if ($src_opt && $src_opt ne $src);
  return if ($dst_opt && $dst_opt ne $dst);
  return if ($srczone && $srczone ne $from);
  return if ($dstzone && $dstzone ne $to);

  # Check time range
  if ($since || $before) {
    my $t = str2time($time_generated);
    return if ($since && $t < $since);
    return if ($before && $t > $before);
  }

  # Increment counters for each field
  $total++;
  $total_src_bytes += $bytes_sent;
  $total_dst_bytes += $bytes_received;
  $protos{$proto}++;
  $srcs{"$src $srcloc"}++;
  $dsts{"$dst $dstloc"}++;
  $src_bytes{"$src $srcloc"} += $bytes_sent;
  $dst_bytes{"$src $srcloc"} += $bytes_received;
  if ($opts{ports}) {
    $sports{"$proto/$sport"}++;
    $dports{"$proto/$dport"}++;
  }
  $rules{$rule}++;
  $actions{$action}++;
  $srclocs{$srcloc}++;
  $dstlocs{$dstloc}++;
  $flows{"$proto $src:$sport -> $dst:$dport"}++ if ($opts{flows}); 

  # Output log line
  print $line,"\n" if ($opts{l});

  # Pretty print log line
  printf $fmt,$time_generated,$devname,$action,$proto,$from,$src,$sport,$srcloc,$to,$dst,$dport,$dstloc,$app,$rule,scalenum($packets),scalenum($bytes) if ($opts{L});
}

#-------------------------------------------------------------------------------
# Convert dotted-quad IP address to 32-bit int
sub ip2dec {
    my ($o1,$o2,$o3,$o4) = split(/\./, $_[0]);
    ($o1 << 24) + ($o2 << 16) + ($o3 << 8) + $o4;
}

#-------------------------------------------------------------------------------
# Pretty print number using metric scale
sub scalenum {
    my ($x) = @_;
    return sprintf("%.3fT", $x/1000000000000) if ($x > 1000000000000);
    return sprintf("%.3fG", $x/1000000000) if ($x > 1000000000);
    return sprintf("%.3fM", $x/1000000) if ($x > 1000000);
    return sprintf("%.3fK", $x/1000) if ($x > 1000);
    return $x;
}

