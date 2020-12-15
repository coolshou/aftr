#!/usr/bin/perl -s

# generate a large aftr.conf

$nnat = ($#ARGV >= 0) ? $ARGV[0] : 10000;

print 
"default pool tcp 8192-65535\
default pool udp 8192-65535\
address endpoint 2001::1\
address icmp 10.0.100.1\
acl6 2001::/48\n";

@proto = ("tcp", "udp");

# generate a pool of public addresses
for ($i = 100; $i <= 199; ++$i) {
    push(@pool, "198.18.200.$i");
    print "pool 198.18.200.$i\n";
}

# generate a pool of local addresses
for ($i = 30; $i < 80; ++$i) {
    push(@local, "10.0.0.$i");
}
for ($i = 80; $i < 130; ++$i) {
    push(@local, "10.0.1.$i");
}
for ($i = 130; $i < 180; ++$i) {
    push(@local, "10.0.2.$i");
}
for ($i = 50; $i < 100; ++$i) {
    push(@local, "192.168.0.$i");
}
for ($i = 100; $i < 150; ++$i) {
    push(@local, "192.168.1.$i");
}
for ($i = 150; $i < 200; ++$i) {
    push(@local, "192.168.2.$i");
}

# generate a ton of nat entries
for ($i = 0; $i < $nnat; $i += $j) {
    # generate a random ipv6 addr
    $tunnel = sprintf("2001:0:0:%x:%x:%x:%x:%x",
		    int(rand(1000)), int(rand(65535)), int(rand(65535)),
		    int(rand(65535)), int(rand(65535)));
    ++$tunnels;

    # assign it a pool address
    $naddr = $pool[int(rand($#pool))];

    # pick local addresses from the same subnet
    $spool = int(rand(6));

    # generate 1-5 nat entries
    for ($j = 0; $j <= int(rand(5)); ++$j) {
	$proto = $proto[int(rand(2))];

	# generate a natted port
	do {
	    # check for collisions
	    $nport = 1024 + int(rand(8192 - 1024));
	} while (defined($nats{"$naddr:$nport:$proto"}));
	$nats{"$naddr:$nport:$proto"} = 1;

	# generate a source port
	do {
	    # there's almost no chance of source collision,
	    # but let's just make sure
	    $saddr = $local[$spool*50 + int(rand(50))];
	    $sport = 1024 + int(rand(8192 - 1024));
	} while (defined($srcs{"$saddr:$sport:$proto"}));
	$srcs{"$saddr:$sport:$proto"} = 1;

	print("nat $tunnel $proto $saddr $sport $naddr $nport\n");
	++$nats;
    }
    ++$nats[$j];
}

if ($v) {
    print STDERR "$tunnels tunnels\n";
    print STDERR "$nats nats\n";
    for ($j = 1; $j <= $#nats; ++$j) {
	print STDERR "$j: $nats[$j]\t" . int($nats[$j]/$nats * 100) . "%\n";
    }
    printf STDERR "avg %.2f nats/tunnel\n", $nats/$tunnels;
}
