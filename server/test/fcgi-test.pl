#!/usr/bin/perl
use strict;
use warnings;

use List::Util 'min';
use Time::HiRes 'time';
use LWP::UserAgent;
use URI;
use URI::Escape qw(uri_escape_utf8);
use HTTP::Date;
use MIME::Base64;
use Digest::HMAC_SHA1 'hmac_sha1';
use Digest::SHA qw(sha1_hex sha1);
use JSON;

$| = 1;

my $BATCH_SIZE = 64*1024;
die "Usage: <[host:]port> <hashfsdir>\n" unless $#ARGV == 1;
my $HASHFS_DIR = $ARGV[1];

sub read_auth {
    open(F, "<", "$HASHFS_DIR/admin.key") || die "cannot open $HASHFS_DIR/admin.key";
    my $auth = readline(*F);
    close(F);
    return $auth;
}

sub random_string {
    my @chars = ('a'..'z', 'A'..'Z', 0..9);
    my $len = shift;
    return join '', map $chars[rand @chars], 1..$len;
}

my $reader = "reader" . (random_string 32);
my $writer = "writer" . (random_string 32);
my $delme = "disposable" . (random_string 32);

# TODO: create $reader and $writer user, and assign privs to them when
# creating the volumes!
my %TOK=('noauth'  => undef,
	 'badauth' => 'aDFoHfmEPg7cHgF1UXZPAnvhGeytwq13+wD/Ozt7BNpO1jUI45hnrQAA',
	 'admin'   => read_auth
     );

my $PUBLIC = everyone(200);
my ($fails, $okies) = (0, 0);
my @cleanupf;
my @cleanupv;
my @cleanupu;
my $cleanupm;
my $in_cleanup = 0;

my $QUERYHOST = 'localhost';
my $NODEHOST = '';
my $PORT = '';
if(is_int($ARGV[0])) {
    $PORT = ':'.$ARGV[0];
    $QUERYHOST .= $PORT;
} elsif(defined $ARGV[0]) {
    $QUERYHOST = $ARGV[0];
    $NODEHOST = $ARGV[0];
}

sub fail {
    return if($in_cleanup);
    print 'FAIL ('.shift().")\n";
    $fails++;
}

sub ok {
    return if($in_cleanup);
    my $msg = str(shift);
    print "ok $msg\n";
    $okies++
}

sub everyone {
    my ($status, $type) = @_;
    die "Invalid status" unless $status > 0;
    return {
	'noauth'  => [ $status, $type ],
	'badauth' => [ 401, undef ],
	$reader  => [ $status, $type ],
	$writer  => [ $status, $type ],
	'admin'   => [ $status, $type ],
    };
}

sub authed_only {
    my ($status, $type) = @_;
    die "Invalid status" unless $status > 0;
    return {
	'noauth'  => [ 401 ],
	'badauth' => [ 401 ],
	$reader  => [ $status, $type ],
	$writer  => [ $status, $type ],
	'admin'   => [ $status, $type ],
    };
}

sub admin_only {
    my ($status, $type) = @_;
    die "Invalid status" unless $status > 0;
    return {
	'noauth'  => [ 401 ],
	'badauth' => [ 401 ],
	$reader  => [ 403 ],
	$writer  => [ 403 ],
	'admin'   => [ $status, $type ],
    };
}

sub writer_only {
    my ($status, $type) = @_;
    die "Invalid status" unless $status > 0;
    return {
	'noauth'  => [ 401 ],
	'badauth' => [ 401 ],
	$reader  => [ 403 ],
	$writer  => [ $status, $type ],
	'admin'   => [ $status, $type ],
    };
}

sub random_data {
    my $len = shift;
    my $r;

    open(F, "<", "/dev/urandom");
    binmode(F);
    read(F, $r, $len);
    close(F);
    return $r;

# this is faster but allocs over 2GB for 160MB
#    return pack('L*', map rand 0x100000000, 1..($len/4)).pack "C*", (map int rand 256, 1..$rem);
}

sub random_data_r {
    my $ref = shift;
    my $len = shift;

    undef $$ref;
    open(F, "<", "/dev/urandom");
    binmode(F);
    read(F, $$ref, $len);
    close(F);
}

sub str {
    my $s = shift;
    return defined $s ? $s : "";
}

sub uri_escape_noslash {
    return join('/',  map(uri_escape_utf8($_), split('/', shift)));
}

sub escape_uri {
    my $vol = shift;
    my $path = shift;

    my $ret = uri_escape_utf8($vol);
    $ret .= '/'.uri_escape_noslash($path) if defined $path;
    return $ret;
}

sub get_json {
    my $json_text = shift or return undef;
    my $json = decode_json $json_text or return undef;
    return $json;
}

sub do_query {
    my $req = shift;
    my $auth = shift;
    my $ua = LWP::UserAgent->new;
    $ua->env_proxy;

    $req->header('Date' => time2str) unless $req->header('Date');
    $req->header('Accept-encoding' => 'gzip,deflate');
    if($auth) {
	my $binauth = decode_base64($auth);
	die "Bad auth token" unless length($binauth) == 42;
	my $auth_id = substr($binauth, 0, 20);
	my $auth_key = substr($binauth, 20, 20);

	my $url = URI->new($req->uri);
	my $blob = join "\n", $req->method, substr($url->path_query, 1), $req->header('Date'), "";
	if($req->content) {
	    $blob .= sha1_hex($req->content)."\n";
	} else {
	    $blob .= sha1_hex('')."\n";
	}
	my $hmac = hmac_sha1($blob, $auth_key);
	$binauth = "$auth_id$hmac\0\0";
	my $auth_string = 'SKY '.encode_base64($binauth);
	$req->header('Authorization' => $auth_string);
    }

    return $ua->request($req);
}

sub bin_to_hex {
    my $s = shift;
    my @chrs = split(//, $s);
    my $h = '';
    $h .= sprintf('%02x', ord($_)) foreach (@chrs);
    return $h;

# For some reason this doesn't work. Long live perl!
#    $s =~ s/(.)/sprintf("%02x",ord($1))/eg;
}

sub hex_to_bin {
    return pack "H*", shift;
}

sub test_reply {
    my $verb = shift;
    my $test = shift;
    my $who = shift;
    my $q = shift;
    my $content = shift;
    my $content_checker = shift;
    foreach (keys(%TOK)) {
	my $expect = $who->{$_};
	next unless $expect;

	my ($exp_st, $exp_ct) = @$expect;
	print "Checking $test ($_)... " unless $in_cleanup;
	my $auth = $TOK{$_};
	my $req = HTTP::Request->new($verb, "http://$QUERYHOST/$q");
	if(defined $content) {
	    $req->content($content);
	} else {
	    $req->header('content-length' => 0);
	}
	my $repl = do_query $req, $auth;
#	print $req->as_string;
#	print $repl->decoded_content;
	if($repl->code != $exp_st) {
	    fail "unexpected status code - got '".$repl->code."' expected: '$exp_st'";
	    next;
	}
	if($exp_ct && $exp_ct ne $repl->content_type) {
	    fail "unexpected content type - got '".$repl->content_type."' expected: '$exp_ct'";
	    next;
	}
	if($exp_ct && $content_checker && !$content_checker->($repl->decoded_content, $_)) {
	    fail "unexpected content: ". $repl->decoded_content;
	    next;
	}
	ok;
    }
}

sub test_skip {
    print shift()." SKIPPED\n";
}

sub test_get {
    return test_reply 'GET', @_;
}

sub test_head {
    return test_reply 'HEAD', @_;
}

sub test_delete {
    return test_reply 'DELETE', @_;
}

sub get_type {
    my $v = shift;
    my $t = ref $v;
    if($t eq '') {
	return 0 unless defined $v;
	return ($v =~ /^[0-9]+$/) ? 1 : 2;
    } elsif($t eq 'HASH') {
	return 3;
    } elsif($t eq 'ARRAY') {
	return 4;
    }
    return 0;
}

sub is_int {
    return get_type(shift) == 1;
}

sub is_string {
    return get_type(shift) == 2;
}

sub is_hash {
    return get_type(shift) == 3;
}

sub is_array {
    return get_type(shift) == 4;
}

sub job_submit {
    my $verb = shift;
    my $q = shift;
    my $content = shift;
    my $auth = shift;
    my $exp_st = shift;

    my $req = HTTP::Request->new($verb, "http://$QUERYHOST/$q");
    $req->content($content);
    my $repl = do_query $req, $auth;
    if($repl->code != $exp_st) {
	fail "job request received an unexpected status code - got '".$repl->code."' expected: '$exp_st'";
	return undef;
    }
    if($exp_st != 200) {
	return '';
    }
    if($repl->content_type ne 'application/json') {
	fail "job request received an unexpected content type - got '".$repl->content_type."' expected: 'application/json'";
	return undef;
    }
    my $json = get_json($repl->decoded_content);
    if(!defined($json) || !is_int($json->{'minPollInterval'}) || !is_int($json->{'maxPollInterval'}) || !defined($json->{'requestId'})) {
	fail "bad reply content to job request";
	return undef;
    }
    return $json->{'requestId'};
}

sub job_result {
    my $jobid = shift;
    my $auth = shift;
    while(1) {
	select(undef, undef, undef, 0.25);
	my $req = HTTP::Request->new('GET', "http://$QUERYHOST/.results/$jobid");
	$req->header('content-length' => 0);
	my $repl = do_query $req, $auth;
#	print $req->as_string;
#	print $repl->decoded_content;

	my $json = get_json $repl->decoded_content;
	if($repl->code != 200) {
	    fail "job result received an unexpected status code - got '".$repl->code."' expected: '200'";
	    return undef;
	}
	if($repl->content_type ne 'application/json') {
	    fail "job result received an unexpected content type - got '".$repl->content_type."' expected: 'application/json'";
	    return undef;
	}
	if(!$json || !is_string($json->{'requestStatus'}) || !is_string($json->{'requestMessage'}) || !defined($json->{'requestId'}) || $json->{'requestId'} ne $jobid) {
	    fail "bad reply content to job result";
	    return undef;
	}
	my $status = $json->{'requestStatus'};
	next if($status eq 'PENDING');
	return ($status, $json->{'requestMessage'});
    }
}

sub test_upload {
    my $test = shift;
    my $who = shift;
    my $file = shift;
    my $vol = shift;
    my $fname = shift;
    my $expect = shift;
    my $meta = shift;
    my $expectrc = shift; #Expected return code for PUT operation
    my $len = length $file;
    my $grow = ($len+0 > 128*1024*1024);

    print "Checking $test ($who)... " unless $in_cleanup;
    my $auth = $TOK{$who};

    # Get volume info
    my $req = HTTP::Request->new('GET', "http://$QUERYHOST/".escape_uri($vol)."?o=locate&size=$len");
    $req->header('content-length' => 0);
    $req->content(undef);

    my $repl = do_query $req, $auth;
#   print $req->as_string;
#   print $repl->decoded_content;
    if($repl->code != 200) {
	fail 'cannot retrieve volume info - bad status '.$repl->code;
	return;
    }
    if($repl->content_type ne 'application/json') {
	fail 'cannot retrieve volume info - bad content type '.$repl->content_type;
	return;
    }
    if(!is_string($repl->header('SX-Cluster')) || !($repl->header('SX-Cluster') =~ /^[^ ]+ \((.*)\)/)) {
	fail 'cannot retrieve volume info - bad server header: '.$repl->header('SX-Cluster');
	return;
    }
    my $salt = $1;
    my $jsobj;
    if(!($jsobj = get_json(str $repl->decoded_content))) {
	fail 'cannot retrieve volume info - bad json';
	return;
    }
    if(!is_int($jsobj->{'blockSize'})) {
	fail 'cannot retrieve volume info - bad block size '.$jsobj->{'blockSize'};
	return;
    }
    my $blocksize = $jsobj->{'blockSize'};

    # Generate file content
    my $off = 0;
    my @blocko;
    if($len % $blocksize) {
	my $tail = (pack "x") x ($blocksize - ($len % $blocksize));
	$file .= $tail;
    }
    my $llen = length $file;
    while ($off + $blocksize <= $llen) {
	push @blocko, $off;
	$off += $blocksize;
    }
    my @hashes = map sha1_hex($salt.substr($file, $blocko[$_], $blocksize)), 0..$#blocko;

    my $timing = time();

    # PUT file
    my $i = 0;
    my $nsent = 0;
    my $nrecv = 0;
    my $token;
    my $blocks_per_loop = 5;
    do {
	my @subhashes = @hashes[$i..min($i+$blocks_per_loop-1, $#hashes)];
	my $content = { 'fileData' => [@subhashes] };
	if($i == 0) {
	    $content->{'fileSize'} = $grow ? 128*1024*1024+1 : $len+0;
	    $content->{'fileMeta'} = $meta if(defined $meta);
	    $req = HTTP::Request->new('PUT', "http://$QUERYHOST/".escape_uri($vol, $fname))
	} else {
	    $content->{'extendSeq'} = $i;
	    $req = HTTP::Request->new('PUT', "http://$QUERYHOST/.upload/$token");
	    if($grow && $i == $blocks_per_loop) {
		$content->{'fileSize'} = $len+0;
	    }
	}
	$req->content_type('application/json');
	$req->content(encode_json $content);
	$repl = do_query $req, $auth;
        if($i == 0 && defined $expectrc) {
            if($expectrc != $repl->code) {
                fail "Unexpected return code: got: ".$repl->code.", expected: $expectrc";
                return;
            }
            if($expectrc != 200) {
                ok "Got expected return code";
                return;
            }
        } else {
            if($repl->code != 200) {
	        fail 'cannot request file upload - bad status '.$repl->code;
	        return;
	    }
        }
	if($repl->content_type ne 'application/json') {
	    fail 'cannot request file upload - bad content type '.$repl->content_type;
	    return;
	}
	if(!($jsobj = get_json(str $repl->decoded_content))) {
	    fail 'cannot request file upload - bad json';
	    return;
	}
	if(defined($token) && $token ne $jsobj->{'uploadToken'}) {
	    fail 'upload token has changed';
	    return;
	}
	$token = $jsobj->{'uploadToken'};
	if(!is_string($token)) {
	    fail 'cannot request file upload - bad upload token';
	    return;
	}
	my $updata = $jsobj->{'uploadData'};
	if(!is_hash($updata)) {
	    fail 'cannot request file upload - bad upload data';
	    return;
	}
	$nsent += $#subhashes+1;
	$nrecv += scalar keys %$updata;

      UPDATA:
	foreach (keys %$updata) {
	    #next if($_ ~~ @subhashes);
	    foreach my $hash_i (@subhashes) {
		next UPDATA if ($hash_i eq $_);
	    }
	    fail "cannot request file upload - unexpected hash $_";
	}

	# PUT blocks
	foreach my $j (0..$#subhashes) {
	    my $hash = $subhashes[$j];
	    next unless defined $updata->{$hash};
	    my $nodes = $updata->{$hash};
	    next unless defined $nodes;
	    delete $updata->{$hash};
	    if(!is_array($nodes) || $#$nodes < 0) {
		fail 'bad node list - bad upload data';
		return;
	    }
	    my $node = $NODEHOST ? $NODEHOST : $nodes->[0].$PORT;
	    $req = HTTP::Request->new('PUT', "http://$node/.data/$blocksize/$token");
	    $req->content(substr($file, $blocko[$i + $j], $blocksize));
	    $repl = do_query $req, $auth;
#    print $req->as_string;
#    print $repl->decoded_content;
	    if($repl->code != 200) {
		fail 'cannot upload hash - bad status '.$repl->code;
		return;
	    }
	}
	$i += $blocks_per_loop;
    } while ($i <= $#hashes);

    $expect = $nsent unless defined $expect;
    if($expect != $nrecv) {
	fail "cannot request file upload - unexpected hash count: expected $expect, returned $nrecv";
	return;
    }

    my $jobid = job_submit 'PUT', ".upload/$token", undef, $auth, 200;
    return unless defined($jobid);
    my ($jobres, $msg) = job_result $jobid, $auth;
    return unless defined($jobres);
    if($jobres ne 'OK') {
	fail "failed to check the result status";
	return;
    }

    $timing = time() - $timing;

    # Locate file
    $req = HTTP::Request->new('GET', "http://$QUERYHOST/".escape_uri($vol).'?o=locate');
    $repl = do_query $req, $auth;
#    print $req->as_string;
#    print $repl->decoded_content;
    if($repl->code != 200) {
	fail 'file location - bad status '.$repl->code;
	return;
    }
    if($repl->content_type ne 'application/json') {
	fail 'file location - bad content type '.$repl->content_type;
	return;
    }
    if(!($jsobj = get_json(str $repl->decoded_content))) {
	fail 'file location - bad json';
	return;
    }

    # GET file
    $req = HTTP::Request->new('GET', "http://$QUERYHOST/".escape_uri($vol, $fname));
    $repl = do_query $req, $auth;
#    print $req->as_string;
#    print $repl->decoded_content;
    if($repl->code != 200) {
	fail 'file content request - bad status '.$repl->code;
	return;
    }
    if($repl->content_type ne 'application/json') {
	fail 'file content request - bad content type '.$repl->content_type;
	return;
    }
    if(!($jsobj = get_json(str $repl->decoded_content))) {
	fail 'file content request - bad json';
	return;
    }
    if(!is_int($jsobj->{'fileSize'}) || $jsobj->{'fileSize'} != $len) {
	fail "file content request - bad size: expected $len, returned ".$jsobj->{'fileSize'};
	return;
    }
    if(!is_int($jsobj->{'blockSize'}) || $jsobj->{'blockSize'} != $blocksize) {
	fail "file content request - bad blocksize: expected $blocksize, returned ".$jsobj->{'blockSize'};
	return;
    }
    my $toget = $jsobj->{'fileData'};
    if(!is_array($toget) || join('',map(keys %$_, @$toget)) ne join('', @hashes)) {
	fail 'file content request - bad file data';
	return;
    }

    # GET file content
    foreach my $j (0..$#hashes) {
	my $hash_j = $hashes[$j];
	my $batch = 0;
	if($j == 0 && $#hashes > 2) {
	    $j++;
	    $hash_j .= $hashes[$j];
	    $batch = 1;
	}
	$req = HTTP::Request->new('GET', "http://$QUERYHOST/.data/$blocksize/$hash_j");
	$repl = do_query $req, $auth;
#    print $req->as_string;
#    print $repl->decoded_content;
	if($repl->code != 200) {
	    fail 'hash request - bad status '.$repl->code;
	    return;
	}
	if($repl->content_type ne 'application/octet-stream') {
	    fail 'hash request - bad content type '.$repl->content_type;
	    return;
	}
	if(length $repl->decoded_content != $blocksize * ($batch + 1)) {
	    fail "hash request - bad length: expected $blocksize, returned ".length $repl->decoded_content;
	    return;
	}
	if($batch && $repl->decoded_content ne substr($file, $blocko[$j-1], $blocksize).substr($file, $blocko[$j], $blocksize)) {
	    fail 'batch hash request - content mismatch';
	    return;
	}
	if(!$batch && $repl->decoded_content ne substr($file, $blocko[$j], $blocksize)) {
	    fail 'hash request - content mismatch';
	    return;
	}
    }

    my $mbps = $len / $timing / 1024 / 1024;
    push @cleanupf, escape_uri($vol, $fname);
    ok "$mbps MB/s";
}


sub test_job {
    my $verb = shift;
    my $test = shift;
    my $who = shift;
    my $q = shift;
    my $content = shift;
    my %rescmp;
    if(shift) {
	%rescmp = ( 'ERROR' => 1, 'OK' => 0 );
    } else {
	%rescmp = ( 'ERROR' => 0, 'OK' => 1 );
    }

    foreach (keys(%TOK)) {
	my $expect = $who->{$_};
	next unless $expect;
	my ($exp_st) = @$expect;
	# {"requestId":"6","minPollInterval":100,"maxPollInterval":6000}
	my $auth = $TOK{$_};

	print "Checking $test ($_)... " unless $in_cleanup;

	my $jobid = job_submit $verb, $q, $content, $auth, $exp_st;
	next unless defined($jobid);
	if($jobid eq '') {
	    ok;
	    next;
	}

	my ($jobres, $msg) = job_result $jobid, $auth;
	if(!defined($rescmp{$jobres})) {
	    fail "unknown status '$jobres')";
	} elsif($rescmp{$jobres}) {
	    ok;
	} else {
	    fail "request failed: unexpected job result ($jobres, $msg)";
	}
    }
}

sub test_put_job {
    return test_job 'PUT', @_;
}

sub test_delete_job {
    return test_job 'DELETE', @_;
}

sub test_mkvol {
    my $oldk = $okies;
    test_put_job @_;
    if(defined($_[2]) && $okies > $oldk) {
	push @cleanupv, $_[2];
    }
}

sub test_create_user {
    my $name = shift;
    my $extra = shift || {};
    my $binu = sha1($name);
    my $bink = random_data(20);
    my $content = { 'userType' => 'normal', 'userKey' => bin_to_hex($bink), %$extra, 'userName' => $name };

    test_put_job "user creation $name...", admin_only(200), '.users', encode_json($content);

    $TOK{$name} = encode_base64($binu . $bink . chr(0) . chr(0));
    push @cleanupu, $name;
}

sub cleanup {
    $SIG{INT} = 'DEFAULT';
    $in_cleanup = 1;
    print "\nCleaning up...";
    foreach my $del (@cleanupf) {
	test_delete_job "file cleanup", {'admin'=>[200]}, $del;
    }
    foreach my $del (@cleanupv) {
	test_delete_job "mass delete on $del", {'admin'=>[200]}, "$del?recursive&filter=*";
	test_delete_job "volume cleanup", {'admin'=>[200]}, $del;
    }
    foreach my $del (@cleanupu) {
	test_delete_job "user cleanup", {'admin'=>[200]}, ".users/$del";
    }
    # Cleanup cluster meta
    if(defined($cleanupm)) {
	test_put_job "cluster meta cleanup", admin_only(200), ".clusterMeta", encode_json({"clusterMeta" => $cleanupm});
    }
    print " done\n";
}


$SIG{INT} = sub { cleanup; exit 1; };


### USER CREATION TESTS ###
# Needed for below tests
test_create_user $reader;
test_create_user $writer;
test_create_user $delme;

### HOMEPAGE TESTS ###
test_get 'cluster', $PUBLIC, '';
test_head 'cluster (HEAD)', $PUBLIC, '/';
test_delete 'cluster (bad method)', {'badauth'=>[401],$reader=>[405],$writer=>[405],'admin'=>[405]}, '';

### CLUSTER TESTS ###
test_get 'list nodes', {'noauth'=>[200,'text/html'],'badauth'=>[401],$reader=>[200,'application/json'],$writer=>[200,'application/json'],'admin'=>[200,'application/json']}, '?nodeList';
test_get 'list nodes (HEAD)', {'noauth'=>[200,'text/html'],'badauth'=>[401],$reader=>[200,'application/json'],$writer=>[200,'application/json'],'admin'=>[200,'application/json']}, '?nodeList';

my $nodesize = 1*1024*1024*1024*1024*1024;
test_get 'cluster status', {'badauth'=>[401],$reader=>[403],$writer=>[403],'admin'=>[200,'application/json']}, '?clusterStatus', undef, sub { my $json = get_json(shift) or return 0; return 0 unless (is_hash($json->{'clusterStatus'}) && is_array($json->{'clusterStatus'}->{'distributionModels'}) && @{$json->{'clusterStatus'}->{'distributionModels'}} == 1); my $dist = $json->{'clusterStatus'}->{'distributionModels'}->[0]; return 0 unless(is_array($dist) && scalar @$dist == 1); $dist = $dist->[0]; return 0 unless (is_hash($dist) && is_string($dist->{'nodeUUID'}) && is_string($dist->{'nodeAddress'}) && is_int($dist->{'nodeCapacity'})); $nodesize = $dist->{'nodeCapacity'}; return 1};


### VOLUME TESTS ###
my $vol = random_string 32;
my $blocksize = 4096;
my $volumesize = 0x40000000;
my $tinyvolumesize = 1024*1024;
my $bigvolumesize = $nodesize+1;

test_mkvol 'volume creation (no content)', admin_only(400), $vol;
test_mkvol 'volume creation (bad content)', admin_only(400), $vol, "{\"owner\":\"admin\",\"volumeSize\":$volumesize";
test_mkvol 'volume creation (bad volume size - too small)', admin_only(400), $vol, '{"owner":"admin","volumeSize":10}';
test_mkvol 'volume creation (bad volume size - too big)', admin_only(400), $vol, "{\"owner\":\"admin\",\"volumeSize\":$bigvolumesize}";
test_mkvol 'volume creation (no owner)', admin_only(400), $vol, "{\"volumeSize\":$volumesize}";
test_mkvol 'volume creation (reserved name)', admin_only(403), '.reserved', "{\"owner\":\"admin\",\"volumeSize\":$volumesize}";
test_mkvol "volume creation", admin_only(200), $vol, "{\"volumeSize\":$volumesize,\"owner\":\"admin\"}";
test_put_job 'granting rights on newly created volume', admin_only(200), $vol."?o=acl", "{\"grant-read\":[\"$reader\",\"$writer\"],\"grant-write\":[\"$writer\"] }";
test_mkvol 'creation of the same volume', admin_only(200), $vol, "{\"owner\":\"admin\",\"volumeSize\":$volumesize}", 1;
test_get 'the newly created volume', authed_only(200, 'application/json'), $vol, undef, sub { my $json = get_json(shift) or return 0; return is_int($json->{'volumeSize'}) && $json->{'volumeSize'} == $volumesize && is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 0 };
test_mkvol 'creation of another volume', admin_only(200), "another.$vol", "{\"volumeSize\":$volumesize,\"owner\":\"admin\"}";
test_put_job 'granting rights on newly created volume', admin_only(200), "another.$vol?o=acl", "{\"grant-read\":[\"$reader\",\"$writer\"],\"grant-write\":[\"$writer\"] }";
test_get 'the newly created volume', authed_only(200, 'application/json'), "another.$vol", undef, sub { my $json = get_json(shift) or return 0; return is_int($json->{'volumeSize'}) && $json->{'volumeSize'} == $volumesize && is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 0 };
test_get 'the old volume again', authed_only(200, 'application/json'), "another.$vol", undef, sub { my $json = get_json(shift) or return 0; return is_int($json->{'volumeSize'}) && $json->{'volumeSize'} == $volumesize && is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 0 };
test_mkvol 'volume creation (negative replica)', admin_only(400), "large$vol", "{\"owner\":\"admin\",\"replicaCount\":-1,\"volumeSize\":$volumesize}";
test_mkvol 'volume creation (replica > nodes)', admin_only(400), "large$vol", "{\"owner\":\"admin\",\"replicaCount\":1000,\"volumeSize\":$tinyvolumesize}", 1;
test_mkvol 'volume creation (non default replica)', admin_only(200), "large$vol", "{\"owner\":\"admin\",\"replicaCount\":1,\"volumeSize\":$volumesize}";
test_put_job 'granting rights on newly created volume', admin_only(200), "large$vol?o=acl", "{\"grant-read\":[\"$reader\",\"$writer\"],\"grant-write\":[\"$writer\"] }";

my $nuke = chr(0x2622);
my $utfvol = "$vol$nuke";
test_mkvol "volume creation (utf-8)", admin_only(200), escape_uri($utfvol), "{\"owner\":\"admin\",\"volumeSize\":$volumesize}";
test_put_job 'granting rights on newly created volume', admin_only(200), escape_uri($utfvol)."?o=acl", "{\"grant-read\":[\"$reader\",\"$writer\"],\"grant-write\":[\"$writer\"] }";
test_get 'the newly created volume', authed_only(200, 'application/json'), escape_uri($utfvol), undef, sub { my $json = get_json(shift) or return 0; return is_int($json->{'volumeSize'}) && $json->{'volumeSize'} == $volumesize && is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 0 };
test_mkvol 'volume creation (with meta)', admin_only(200), "meta.$vol", "{\"owner\":\"admin\",\"volumeSize\":$volumesize,\"volumeMeta\":{\"one\":\"01\",\"two\":\"2222\",\"three\":\"333333\"}}";
test_put_job 'granting rights on newly created volume', admin_only(200), "meta.$vol?o=acl", "{\"grant-read\":[\"$reader\",\"$writer\"],\"grant-write\":[\"$writer\"] }";
test_get 'the newly created volume', authed_only(200, 'application/json'), "meta.$vol?o=locate&volumeMeta", undef, sub { my $json = get_json(shift) or return 0; return is_array($json->{'nodeList'}) && is_hash($json->{'volumeMeta'}) && (scalar keys %{$json->{'volumeMeta'}} == 3) && $json->{'volumeMeta'}->{'one'} eq '01' && $json->{'volumeMeta'}->{'two'} eq '2222' && $json->{'volumeMeta'}->{'three'} eq '333333' };
test_get 'the newly created volume for meta ', {'badauth'=>[401],$reader=>[200,'application/json'],$writer=>[200,'application/json'],'admin'=>[200,'application/json']}, "?volumeList&volumeMeta", undef, sub { my $json = get_json(shift) or return 0; if(!(is_hash($json->{'volumeList'}) && is_hash($json->{'volumeList'}->{"meta.$vol"}))) { return 0; } my $meta = $json->{'volumeList'}->{"meta.$vol"}->{'volumeMeta'}; return is_hash($meta) && (scalar keys %{$meta} == 3) && $meta->{'one'} eq '01' && $meta->{'two'} eq '2222' && $meta->{'three'} eq '333333'; };

test_mkvol 'volume creation (with bad meta)', admin_only(400), "badmeta.$vol", "{\"owner\":\"admin\",\"volumeSize\":$volumesize,\"volumeMeta\":{\"badval\":\"0dd\"}}";
test_mkvol 'volume creation (max meta key size)', admin_only(200), "maxmetakey.$vol", "{\"owner\":\"admin\",\"volumeSize\":$tinyvolumesize,\"volumeMeta\":{\"".('A' x 256)."\":\"acab\"}}";
test_mkvol 'volume creation (meta key too long)', admin_only(400), "badmeta2.$vol", "{\"owner\":\"admin\",\"volumeSize\":$tinyvolumesize,\"volumeMeta\":{\"".('A' x 257)."\":\"acab\"}}";
test_mkvol 'volume creation (max meta value size)', admin_only(200), "maxmetaval.$vol", "{\"owner\":\"admin\",\"volumeSize\":$tinyvolumesize,\"volumeMeta\":{\"key\":\"".('a' x 2048)."\"}}";
test_mkvol 'volume creation (meta value too long)', admin_only(400), "badmeta3.$vol", "{\"owner\":\"admin\",\"volumeSize\":$tinyvolumesize,\"volumeMeta\":{\"key\":\"".('a' x 2049)."\"}}";
my $metaitems = join(',', map { qq{"$_":"acab"} } 0..127);
test_mkvol 'volume creation (max meta items)', admin_only(200), "maxmetaitems.$vol", "{\"owner\":\"admin\",\"volumeSize\":$tinyvolumesize,\"volumeMeta\":{$metaitems}}";
test_mkvol 'volume creation (too many meta items)', admin_only(400), "badmeta4.$vol", "{\"owner\":\"admin\",\"volumeSize\":$tinyvolumesize,\"volumeMeta\":{$metaitems,\"toomany\":\"acab\"}}";


# Tiny volume will be used for volume size enforcement tests
test_mkvol "volume creation (tiny volume)", admin_only(200), "tiny$vol", "{\"volumeSize\":$tinyvolumesize,\"owner\":\"$writer\"}";
test_put_job 'granting rights on newly created volume', {'badauth'=>[401],$reader=>[403],$writer=>[200],'admin'=>[200]}, "tiny$vol?o=acl", "{\"grant-read\":[\"$reader\"],\"grant-write\":[] }";
test_get 'the newly created volume', authed_only(200, 'application/json'), "tiny$vol", undef, sub { my $json = get_json(shift) or return 0; return is_int($json->{'volumeSize'}) && $json->{'volumeSize'} == $tinyvolumesize && is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 0 };

# Misc volume used to test user deletion and revisions
test_mkvol "volume creation (misc volume)", admin_only(200), "misc$vol", "{\"volumeSize\":$tinyvolumesize,\"owner\":\"$delme\",\"replicaCount\":1,\"maxRevisions\":2}";
test_get 'checking volume ownership', admin_only(200, 'application/json'), "misc$vol?o=acl&manager", undef, sub { my $json = get_json(shift);
    my %is_priv   = map { $_, 1 } @{$json->{$delme}};
    return is_array($json->{$delme}) && $is_priv{'owner'}; };
test_delete_job "user deletion", admin_only(200), ".users/$delme";
test_get 'checking volume ownership', admin_only(200, 'application/json'), "misc$vol?o=acl&manager", undef, sub { 
    my $json = get_json(shift);
    my %is_priv = ();
    foreach (@{$json->{'admin'}}) { $is_priv{$_} = 1 };
    return is_array($json->{'admin'}) && $is_priv{'owner'} && !exists $json->{$delme}; };

### FILE TESTS ###
my $blk;

test_upload 'file upload (small blocksize)', $writer, random_data($blocksize), $vol, '1bs';
test_upload 'file upload (small blocksize + 500)', $writer, random_data($blocksize + 500), $vol, '1bs+1', undef, {};
test_upload 'file upload (0.5x small blocksize)', $writer, random_data($blocksize / 2), $vol, '0.5bs', undef, { 'key1' => '6669727374', 'key2' => '7365636f6e64' };
test_upload 'file upload (empty file)', $writer, '', $vol, 'empty';
test_upload 'file upload (small blocksize)', 'admin', random_data ($blocksize), $vol, 'adm';
#test_upload 'file upload (small blocksize, sequence)', $writer, 'a'x$blocksize, $vol, 'seq', 0;
random_data_r(\$blk, $blocksize);
test_upload 'file upload (smal blocksize, repeating)', $writer, $blk.random_data($blocksize).$blk, $vol, 'rep', 2;
test_upload 'file upload (small blocksize, previous)', $writer, $blk, $vol, 'prev', 0;
test_upload 'file upload (/)', $writer, random_data($blocksize), $vol, 'file';
test_upload 'file upload (/dir)', $writer, random_data($blocksize), $vol, 'dir/file';
test_upload 'file upload (/file)', $writer, random_data($blocksize), $vol, 'file/file';
my $utffile = "file$nuke";
test_upload 'file upload (utf-8)', $writer, random_data($blocksize), $utfvol, $utffile;

$blocksize = 16*1024;
random_data_r(\$blk, 16*$blocksize);
test_upload 'file upload (mid blocksize)', $writer, $blk, "large$vol", '1bs';
random_data_r(\$blk, 16*$blocksize + 500);
test_upload 'file upload (mid blocksize + 500)', $writer, $blk, "large$vol", '1bs+1';
random_data_r(\$blk, 16*$blocksize);
test_upload 'file upload (mid blocksize)', 'admin', $blk, "large$vol", 'adm';
#test_upload 'file upload (mid blocksize, sequence)', $writer, 'a'x$blocksize, "large$vol", 'seq', 0;
random_data_r(\$blk, $blocksize);
test_upload 'file upload (mid blocksize, repeating)', $writer, $blk.random_data(14*$blocksize).$blk, "large$vol", 'rep', 15;
test_upload 'file upload (mid blocksize, previous)', $writer, $blk x 16, "large$vol", 'prev', 0;

$blocksize = 1*1024*1024;

random_data_r(\$blk, 160*$blocksize);
test_upload 'file upload (big blocksize)', $writer, $blk, "large$vol", '1bs';
random_data_r(\$blk, 160*$blocksize + 500);
test_upload 'file upload (big blocksize + 500)', $writer, $blk, "large$vol", '1bs+1';
random_data_r(\$blk, $blocksize);
test_upload 'file upload (big blocksize, repeating)', $writer, ($blk x 64).random_data($blocksize).($blk x 64), "large$vol", 'rep', 2;
test_upload 'file upload (big blocksize, previous)', $writer, $blk x 160, "large$vol", 'prev', 0;

test_get 'get min growable size', authed_only(200, 'application/json'), "large$vol?o=locate&size=growable", undef, sub { my $json = get_json(shift) or return 0; return is_int($json->{'growableSize'}) && $json->{'growableSize'} == 128*1024*1024+1 && is_int($json->{'blockSize'}) && $json->{'blockSize'} == $blocksize; };

### Check quota handling ###
# This file should not be allowed to be uploaded because quota will be exceeded by one byte
test_upload 'file upload: (exceeding volume capacity)', $writer, random_data($tinyvolumesize-length('toobig')+1), "tiny$vol", 'toobig', undef, {}, 413;
# Check if quota will be enforced also for file with metadata (-meta value length: 10/2=5, +1 byte to exceed)
test_upload 'file upload (exceeding volume capacity (meta))', $writer, random_data($tinyvolumesize-length('toobig')-length('somemeta')-4), "tiny$vol", 'toobig', undef, {'somemeta'=> "ffaabb0011"}, 413;
# This should return 200
test_upload 'file upload (with meta, should not exceed volume capacity)', $writer, random_data($tinyvolumesize-length('toobig')-length('somemeta')-5), "tiny$vol", 'toobig', undef, {'somemeta'=> "ffaabb0011"};
# Checking volume owner quota handing
test_delete_job "Wiping tiny$vol contents", {'badauth'=>[401],$reader=>[403],$writer=>[200]}, "tiny$vol/toobig";
my $mediumvolumesize = $tinyvolumesize * 10;
test_mkvol "volume creation (medium volume)", admin_only(200), "medium$vol", "{\"volumeSize\":$mediumvolumesize,\"owner\":\"$writer\"}";
test_get 'the newly created volume', {'badauth'=>[401],$reader=>[403],$writer=>[200, 'application/json'],'admin'=>[200, 'application/json']}, "medium$vol", undef, sub { my $json = get_json(shift) or return 0; return is_int($json->{'volumeSize'}) && $json->{'volumeSize'} == $mediumvolumesize && is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 0 };
# Check if we can change $writer quota
test_put_job "setting owner quota for $writer", admin_only(200), ".users/$writer", "{\"quota\":$tinyvolumesize}";
# Check if quota has been set up properly
test_get "$writer quota", admin_only(200,'application/json'), ".users/$writer?quota", undef, sub { my $json_raw = shift; my $json = get_json($json_raw) or return 0; return is_int($json->{'userQuota'}) && $json->{'userQuota'} == $tinyvolumesize; };
# This should return 200
test_upload 'file upload', $writer, random_data($tinyvolumesize-length('toobig')), "tiny$vol", 'toobig';
# Check if volume usage is computed correctly
test_get "$writer quota usage", {$writer=>[200,'application/json']}, ".self", undef, sub { my $json_raw = shift; my $json = get_json($json_raw) or return 0; return is_hash($json->{$writer}) && is_int($json->{$writer}->{'userQuota'}) && $json->{$writer}->{'userQuota'} == $tinyvolumesize && is_int($json->{$writer}->{'userQuotaUsed'}) && $json->{$writer}->{'userQuotaUsed'} == $tinyvolumesize; };
# This file should not be allowed to be uploaded because $writer user quota will be exceeded (data on the other volume owned by $writer is present)
test_upload 'file upload: (exceeding volume owner quota)', $writer, '', "medium$vol", 'empty', undef, {}, 413;
test_delete_job "Wiping tiny$vol contents", {'badauth'=>[401],$reader=>[403],$writer=>[200]}, "tiny$vol/toobig";
# This should return 200 now (file size is the length of file name)
test_upload 'file upload', $writer, '', "medium$vol", 'empty';
# This file should not be allowed to be uploaded because $writer user quota will be exceeded (data on the other volume owned by $writer is present)
test_upload 'file upload (exceeding volume owner quota)', $writer, random_data($tinyvolumesize-length('toobig')), "tiny$vol", 'toobig', undef, {}, 413;
# Check if we can disable $writer quota
test_put_job "disabling owner quota for $writer", admin_only(200), ".users/$writer", "{\"quota\":0}";
# Check if quota has been set up properly
test_get "$writer quota", admin_only(200,'application/json'), ".users/$writer?quota", undef, sub { my $json_raw = shift; my $json = get_json($json_raw) or return 0; return is_int($json->{'userQuota'}) && $json->{'userQuota'} == 0; };
# Check if volume usage is computed correctly
test_get "$writer quota usage", {$writer=>[200,'application/json']}, ".self", undef, sub { my $json_raw = shift; my $json = get_json($json_raw) or return 0; return is_hash($json->{$writer}) && is_int($json->{$writer}->{'userQuota'}) && $json->{$writer}->{'userQuota'} == 0 && is_int($json->{$writer}->{'userQuotaUsed'}) && $json->{$writer}->{'userQuotaUsed'} == length('empty'); };
# This should return 200 now
test_upload 'file upload', $writer, random_data($tinyvolumesize-length('toobig')), "tiny$vol", 'toobig';
# Check if volume usage is computed correctly
test_get "$writer quota usage", {$writer=>[200,'application/json']}, ".self", undef, sub { my $json_raw = shift; my $json = get_json($json_raw) or return 0; return is_hash($json->{$writer}) && is_int($json->{$writer}->{'userQuota'}) && $json->{$writer}->{'userQuota'} == 0 && is_int($json->{$writer}->{'userQuotaUsed'}) && $json->{$writer}->{'userQuotaUsed'} == length('empty') + $tinyvolumesize; };
test_put_job "setting invalid quota for $writer (negative)", {'badauth'=>[401],$reader=>[403],$writer=>[403],'admin'=>[400]}, ".users/$writer", "{\"quota\":-1}";
test_put_job "setting invalid quota for $writer (too small)", {'badauth'=>[401],$reader=>[403],$writer=>[403],'admin'=>[400]}, ".users/$writer", "{\"quota\":1048575}"; # 1MB is the lowest accepted value


test_get 'listing all files', authed_only(200, 'application/json'), $vol, undef, sub { my $json = get_json(shift) or return 0; return is_hash($json->{'fileList'}) && is_hash($json->{'fileList'}->{'/empty'}) && is_int($json->{'fileList'}->{'/empty'}->{'fileSize'}) && $json->{'fileList'}->{'/empty'}->{'fileSize'} == 0 && is_int($json->{'fileList'}->{'/empty'}->{'blockSize'}) && $json->{'fileList'}->{'/empty'}->{'blockSize'} == 4096 && is_int($json->{'fileList'}->{'/empty'}->{'createdAt'}) && is_string($json->{'fileList'}->{'/empty'}->{'fileRevision'}) };
test_get 'listing files - filter exact', authed_only(200, 'application/json'), "$vol?filter=file", undef, sub { my $json = get_json(shift) or return 0; return is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 2 && is_hash($json->{'fileList'}->{'/file'}) };
test_get 'listing files - filter f*le', authed_only(200, 'application/json'), "$vol?filter=f*le", undef, sub { my $json = get_json(shift) or return 0; return is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 2 && is_hash($json->{'fileList'}->{'/file'}) };
test_get 'listing files - filter *file', authed_only(200, 'application/json'), "$vol?filter=*file", undef, sub { my $json = get_json(shift) or return 0; return is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 2 && is_hash($json->{'fileList'}->{'/file'})  };
test_get 'listing files - filter *file*', authed_only(200, 'application/json'), "$vol?filter=*file*", undef, sub { my $json = get_json(shift) or return 0; return is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 2 && is_hash($json->{'fileList'}->{'/file'})  };
test_get 'listing files - filter f?l?', authed_only(200, 'application/json'), "$vol?filter=f?l?", undef, sub { my $json = get_json(shift) or return 0; return is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 2 && is_hash($json->{'fileList'}->{'/file'}) };
test_get 'listing files - filter [Ff][Ii][Ll][Ee]', authed_only(200, 'application/json'), "$vol?filter=[Ff][Ii][Ll][Ee]", undef, sub { my $json = get_json(shift) or return 0; return is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 2 && is_hash($json->{'fileList'}->{'/file'}) };
test_get 'listing files - filter /file', authed_only(200, 'application/json'), "$vol?filter=/file", undef, sub { my $json = get_json(shift) or return 0; return is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 2 && is_hash($json->{'fileList'}->{'/file'})  };
test_get 'listing files - filter /dir/', authed_only(200, 'application/json'), "$vol?filter=/dir/", undef, sub { my $json = get_json(shift) or return 0; return is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 1 && is_hash($json->{'fileList'}->{'/dir/file'}) };
test_get 'listing files - filter /dir/file', authed_only(200, 'application/json'), "$vol?filter=/dir/file", undef, sub { my $json = get_json(shift) or return 0; return is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 1 && is_hash($json->{'fileList'}->{'/dir/file'}); };
test_get 'listing files (utf-8)', authed_only(200, 'application/json'), escape_uri($utfvol), undef, sub { my $json = get_json(shift) or return 0; return is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 1 && is_hash($json->{'fileList'}->{"/$utffile"});};

### Check listing files more precisely (for lscache changes testing) ###

### Make files tree on volume: ###
# vol/tree
# vol/tree/a/a
# vol/tree/a/b
# vol/tree/a/c
# vol/tree/b
# vol/tree/b/a
# vol/tree/b/b
# vol/tree/[]
# vol/tree/[]/a
# vol/tree/[]/\a
# vol/tree/[]/\a/a
# vol/tree/[]/?*\

test_upload 'file upload (tree)', $writer, '', $vol, 'tree';
test_upload 'file upload (tree/a/a)', $writer, '', $vol, 'tree/a/a';
test_upload 'file upload (tree/a/b)', $writer, '', $vol, 'tree/a/b';
test_upload 'file upload (tree/a/c)', $writer, '', $vol, 'tree/a/c';
test_upload 'file upload (tree/b)', $writer, '', $vol, 'tree/b';
test_upload 'file upload (tree/b/a)', $writer, '', $vol, 'tree/b/a';
test_upload 'file upload (tree/b/b)', $writer, '', $vol, 'tree/b/b';
test_upload 'file upload (tree/[])', $writer, '', $vol, 'tree/[]';
test_upload 'file upload (tree/[]/a)', $writer, '', $vol, 'tree/[]/a';
test_upload 'file upload (tree/[]/\a)', $writer, '', $vol, 'tree/[]/\a';
test_upload 'file upload (tree/[]/\a/a)', $writer, '', $vol, 'tree/[]/\a/a';
test_upload 'file upload (tree/[]/?*\\', $writer, '', $vol, 'tree/[]/?*\\';

# List only 'tree' file (fakedir will also be returned)
test_get 'listing \'tree\' files', authed_only(200, 'application/json'), "$vol?filter=tree", undef,
    sub {
        my $json_raw = shift;
        my $json = get_json($json_raw) or return 0;
        return 0 unless is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 2;
        return 0 unless is_hash($json->{'fileList'}->{'/tree'});
        my $f = $json->{'fileList'}->{'/tree'} or return 0;
        return 0 unless is_int($f->{'fileSize'}) && $f->{'fileSize'} == 0 && is_int($f->{'blockSize'}) && $f->{'blockSize'} == 4096;
        return 0 unless is_hash($json->{'fileList'}->{'/tree/'});
    };

# List all files from tree
test_get 'listing all \'tree/\' files', authed_only(200, 'application/json'), "$vol?filter=tree/", undef,
    sub {
        my $json_raw = shift;
        my $json = get_json($json_raw) or return 0;
        return 0 unless is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 5;
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]'});
        my $f = $json->{'fileList'}->{'/tree/[]'} or return 0;
        return 0 unless is_int($f->{'fileSize'}) && $f->{'fileSize'} == 0 && is_int($f->{'blockSize'}) && $f->{'blockSize'} == 4096;
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/a/'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/b'});
        $f = $json->{'fileList'}->{'/tree/b'} or return 0;
        return 0 unless is_int($f->{'fileSize'}) && $f->{'fileSize'} == 0 && is_int($f->{'blockSize'}) && $f->{'blockSize'} == 4096;
        return 0 unless is_hash($json->{'fileList'}->{'/tree/b/'});
    };

# List all files from 'tree' (recursively)
test_get 'listing all \'tree\' files (recursively)', authed_only(200, 'application/json'), "$vol?filter=tree&recursive", undef,
    sub {
        my $json_raw = shift;
        my $json = get_json($json_raw) or return 0;
        return 0 unless is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 12;
        return 0 unless is_hash($json->{'fileList'}->{'/tree'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/a/a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/a/b'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/a/c'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/b'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/b/a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/b/b'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/\a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/\a/a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/?*\\'});
    };

# List all files from 'tree' after 'tree/a'
test_get 'listing all \'tree\' files after /tree/a', authed_only(200, 'application/json'), "$vol?filter=tree/&after=tree/a", undef,
    sub {
        my $json_raw = shift;
        my $json = get_json($json_raw) or return 0;
        return 0 unless is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 3;
        return 0 unless is_hash($json->{'fileList'}->{'/tree/a/'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/b'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/b/'});
    };

# List all files from 'tree/??/' (recursively)
test_get 'listing all \'tree/??/\' files (recursively)', authed_only(200, 'application/json'), "$vol?filter=tree/??/&recursive", undef,
    sub {
        my $json_raw = shift;
        my $json = get_json($json_raw) or return 0;
        return 0 unless is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 4;
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/\a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/\a/a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/?*\\'});
    };

# List 'tree/\[\]/' (recursively)
test_get 'listing all \'tree/\[\]/\' files (recursively)', authed_only(200, 'application/json'), "$vol?filter=tree/\[\]/&recursive", undef,
    sub {
        my $json_raw = shift;
        my $json = get_json($json_raw) or return 0;
        return 0 unless is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 4;
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/\a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/\a/a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/?*\\'});
    };

# List 'tree/??/\[abc]''
test_get 'listing all \'tree/??/\\[abc]\' files', authed_only(200, 'application/json'), "$vol?filter=tree/??/\\\\[abc]", undef,
    sub {
        my $json_raw = shift;
        my $json = get_json($json_raw) or return 0;
        return 0 unless is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 2;
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/\a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/\a/'});
    };

# List 'tree/??/\[abc]'' (recursively)
test_get 'listing all \'tree/??/\\[abc]\' files (recursively)', authed_only(200, 'application/json'), "$vol?filter=tree/??/\\\\[abc]&recursive", undef,
    sub {
        my $json_raw = shift;
        my $json = get_json($json_raw) or return 0;
        return 0 unless is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 2;
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/\a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/\a/a'});
    };

# List 'tree/*/\?'' (recursively)
test_get 'listing all \'tree/*/\\?\' files (recursively)', authed_only(200, 'application/json'), "$vol?filter=tree/*/\\\\?&recursive", undef,
    sub {
        my $json_raw = shift;
        my $json = get_json($json_raw) or return 0;
        return 0 unless is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 2;
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/\a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/\a/a'});
    };

# List 'tree/*/*\*''
test_get 'listing all \'tree/*/\\*\' files', authed_only(200, 'application/json'), "$vol?filter=tree/*/*\\\\*", undef,
    sub {
        my $json_raw = shift;
        my $json = get_json($json_raw) or return 0;
        return 0 unless is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 3;
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/\a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/\a/'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/?*\\'});
    };

# List  'tree/[ab]/[ab]''
test_get 'listing all \'tree/[ab]/[ab]\' files', authed_only(200, 'application/json'), "$vol?filter=tree/[ab]/[ab]", undef,
    sub {
        my $json_raw = shift;
        my $json = get_json($json_raw) or return 0;
        return 0 unless is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 4;
        return 0 unless is_hash($json->{'fileList'}->{'/tree/a/a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/a/b'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/b/a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/b/b'});
    };

# List  'tree/*/''
test_get 'listing all \'tree/*/\' files', authed_only(200, 'application/json'), "$vol?filter=tree/*/", undef,
    sub {
        my $json_raw = shift;
        my $json = get_json($json_raw) or return 0;
        return 0 unless is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 9;
        return 0 unless is_hash($json->{'fileList'}->{'/tree/a/a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/a/b'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/a/c'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/b/a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/b/b'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/\a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/\a/'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/?*\\'});
    };

### Check mass delete operation ###
test_delete_job "mass delete on $vol", {'badauth'=>[401],$reader=>[403],$writer=>[200]}, "$vol?filter=/tree/?/a";

# List  'tree/*/' - Now it should not contain /tree/a/a and /tree/b/a files dropped in preceding query
test_get 'listing all \'tree/*/\' files', authed_only(200, 'application/json'), "$vol?filter=tree/*/", undef,
    sub {
        my $json_raw = shift;
        my $json = get_json($json_raw) or return 0;
        return 0 unless is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 7;
        return 0 unless is_hash($json->{'fileList'}->{'/tree/a/b'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/a/c'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/b/b'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/\a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/\a/'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/?*\\'});
    };

# Delete /tree/a/b, /tree/a/c, /tree/b/b
test_delete_job "mass delete on $vol", {'badauth'=>[401],$reader=>[403],'admin'=>[200]}, "$vol?filter=/tree/[ab]/*";
# List  'tree/*/'
test_get 'listing all \'tree/*/\' files', authed_only(200, 'application/json'), "$vol?filter=tree/*/", undef,
    sub {
        my $json_raw = shift;
        my $json = get_json($json_raw) or return 0;
        return 0 unless is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 4;
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/\a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/\a/'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/?*\\'});
    };





### Check mass rename operation ###
test_get 'listing all \'tree/\' files', authed_only(200, 'application/json'), "$vol?filter=tree/&recursive", undef,
    sub {
        my $json_raw = shift;
        my $json = get_json($json_raw) or return 0;
        return 0 unless is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 6;
        return 0 unless is_hash($json->{'fileList'}->{'/tree/b'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/\a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/\a/a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/?*\\'});
    };

# Rename /tree to /treee
test_put_job "mass rename on $vol (rename /tree to /treee)", {'badauth'=>[401],$reader=>[403],$writer=>[200]}, "$vol?source=tree/&dest=treee/&recursive";
# List  'treee/' -> check if /tree directory has been correctly renamed to /treee
test_get 'listing all \'treee/\' files', authed_only(200, 'application/json'), "$vol?filter=treee/&recursive", undef,
    sub {
        my $json_raw = shift;
        my $json = get_json($json_raw) or return 0;
        return 0 unless is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 6;
        return 0 unless is_hash($json->{'fileList'}->{'/treee/b'});
        return 0 unless is_hash($json->{'fileList'}->{'/treee/[]'});
        return 0 unless is_hash($json->{'fileList'}->{'/treee/[]/a'});
        return 0 unless is_hash($json->{'fileList'}->{'/treee/[]/\a'});
        return 0 unless is_hash($json->{'fileList'}->{'/treee/[]/\a/a'});
        return 0 unless is_hash($json->{'fileList'}->{'/treee/[]/?*\\'});
    };

test_get 'listing all \'tree/\' files', authed_only(200, 'application/json'), "$vol?filter=tree/*", undef,
    sub {
        my $json_raw = shift;
        my $json = get_json($json_raw) or return 0;
        return 0 unless is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 0;
    };

# Rename /treee again to /tree
test_put_job "mass rename on $vol (rename /treee to /tree)", {'badauth'=>[401],$reader=>[403],$writer=>[200]}, "$vol?source=treee/&dest=tree/&recursive";
# List  'tree/' recursively
test_get 'listing all \'tree/\' files', authed_only(200, 'application/json'), "$vol?filter=tree/&recursive", undef,
    sub {
        my $json_raw = shift;
        my $json = get_json($json_raw) or return 0;
        return 0 unless is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 6;
        return 0 unless is_hash($json->{'fileList'}->{'/tree/b'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/\a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/\a/a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/?*\\'});
    };
test_get 'listing all \'treee/\' files', authed_only(200, 'application/json'), "$vol?filter=treee/*", undef,
    sub {
        my $json_raw = shift;
        my $json = get_json($json_raw) or return 0;
        return 0 unless is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 0;
    };


# Rename /tree/b to /tree/c
test_put_job "mass rename on $vol (rename /tree/[b] to /tree/c)", {'badauth'=>[401],$reader=>[403],$writer=>[200]}, "$vol?source=tree/[b]&dest=tree/c&recursive";
# List  'tree/' recursively
test_get 'listing all \'tree/\' files', authed_only(200, 'application/json'), "$vol?filter=tree/&recursive", undef,
    sub {
        my $json_raw = shift;
        my $json = get_json($json_raw) or return 0;
        return 0 unless is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 6;
        return 0 unless is_hash($json->{'fileList'}->{'/tree/c'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/\a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/\a/a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/?*\\'});
    };


# Rename /tree/[]/ to /tree/x/
test_put_job "mass rename on $vol (rename /tree/\\[\\]/ to /tree/x/)", {'badauth'=>[401],$reader=>[403],$writer=>[200]}, "$vol?source=tree/\\[\\]/&dest=tree/x/&recursive";
# List  'tree/' recursively
test_get 'listing all \'tree/\' files', authed_only(200, 'application/json'), "$vol?filter=tree/&recursive", undef,
    sub {
        my $json_raw = shift;
        my $json = get_json($json_raw) or return 0;
        return 0 unless is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 6;
        return 0 unless is_hash($json->{'fileList'}->{'/tree/c'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/x/a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/x/\a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/x/\a/a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/x/?*\\'});
    };


# Try to rename /tree/x/ to /tree/z, should fail, because z is not a directory
test_put_job "mass rename on $vol (rename /tree/x/ to /tree/z)", {'badauth'=>[401],$reader=>[403],$writer=>[400]}, "$vol?source=tree/x/&dest=tree/z&recursive";
# List  'tree/' recursively (not changed now)
test_get 'listing all \'tree/\' files', authed_only(200, 'application/json'), "$vol?filter=tree/&recursive", undef,
    sub {
        my $json_raw = shift;
        my $json = get_json($json_raw) or return 0;
        return 0 unless is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 6;
        return 0 unless is_hash($json->{'fileList'}->{'/tree/c'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/x/a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/x/\a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/x/\a/a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/x/?*\\'});
    };


# Rename /tree/c to /tree/d with preceding slashes passed as source and dest
test_put_job "mass rename on $vol (rename /tree/c to /tree/d with leading slashes)", {'badauth'=>[401],$reader=>[403],$writer=>[200]}, "$vol?source=/tree/c&dest=tree/d";
test_put_job "mass rename on $vol (rename /tree/d to /tree/c with leading slashes)", {'badauth'=>[401],$reader=>[403],$writer=>[200]}, "$vol?source=/tree/d&dest=/tree/c";
test_put_job "mass rename on $vol (rename /tree/c to /tree/d with leading slashes)", {'badauth'=>[401],$reader=>[403],$writer=>[200]}, "$vol?source=tree/c&dest=/tree/d";
# List  'tree/' recursively (not changed now)
test_get 'listing all \'tree/\' files', authed_only(200, 'application/json'), "$vol?filter=tree/&recursive", undef,
    sub {
        my $json_raw = shift;
        my $json = get_json($json_raw) or return 0;
        return 0 unless is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 6;
        return 0 unless is_hash($json->{'fileList'}->{'/tree/d'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/x/a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/x/\a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/x/\a/a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/x/?*\\'});
    };



# Rename /tree/x/a to /tree/[] (should overwrite the existing file and correctly reduce x/ from path)
test_put_job "mass rename on $vol (overwrite existing file)", {'badauth'=>[401],$reader=>[403],$writer=>[200]}, "$vol?source=tree/x/a&dest=tree/[]&recursive";
# List  'tree/' recursively (not changed now)
test_get 'listing all \'tree/\' files', authed_only(200, 'application/json'), "$vol?filter=tree/&recursive", undef,
    sub {
        my $json_raw = shift;
        my $json = get_json($json_raw) or return 0;
        return 0 unless is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 5;
        return 0 unless is_hash($json->{'fileList'}->{'/tree/d'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/x/\a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/x/\a/a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/x/?*\\'});
    };



# Rename /tree/x/\a to /tree/a (use globbing '[dx]' and '??' for it)
test_put_job "mass rename on $vol (rename /tree/[dx]/??/? to /tree/a)", {'badauth'=>[401],$reader=>[403],$writer=>[200]}, "$vol?source=tree/[dx]/??/?&dest=tree/a&recursive";
# List  'tree/' recursively (not changed now)
test_get 'listing all \'tree/\' files', authed_only(200, 'application/json'), "$vol?filter=tree/&recursive", undef,
    sub {
        my $json_raw = shift;
        my $json = get_json($json_raw) or return 0;
        return 0 unless is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 5;
        return 0 unless is_hash($json->{'fileList'}->{'/tree/a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/d'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/x/\a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/x/?*\\'});
    };


# Rename /tree/[ad] to the volume root (use globbing '[ad]')
test_get 'listing files matching pattern \'[ad]\'', authed_only(200, 'application/json'), "$vol?filter=[ad]&recursive", undef,
    sub {
        my $json_raw = shift;
        my $json = get_json($json_raw) or return 0;
        return 0 unless is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 0;
    };

test_put_job "mass rename on $vol (rename /tree/[ad] to /)", {'badauth'=>[401],$reader=>[403],$writer=>[200]}, "$vol?source=tree/[ad]&dest=&recursive";
# List  'tree/' recursively (not changed now)
test_get 'listing all \'tree/\' files', authed_only(200, 'application/json'), "$vol?filter=tree/&recursive", undef,
    sub {
        my $json_raw = shift;
        my $json = get_json($json_raw) or return 0;
        return 0 unless is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 3;
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/x/\a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/x/?*\\'});
    };

test_get 'listing files matching pattern \'[ad]\'', authed_only(200, 'application/json'), "$vol?filter=[ad]&recursive", undef,
    sub {
        my $json_raw = shift;
        my $json = get_json($json_raw) or return 0;
        return 0 unless is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 2;
        return 0 unless is_hash($json->{'fileList'}->{'/a'});
        return 0 unless is_hash($json->{'fileList'}->{'/d'});
    };

# Test non-recursive mass rename
test_put_job "mass rename on $vol (rename /[ad] to /tree)", {'badauth'=>[401],$reader=>[403],$writer=>[200]}, "$vol?source=[ad]&dest=tree/";
test_put_job "mass rename on $vol (rename /tree/a to /tree/x)", {'badauth'=>[401],$reader=>[403],$writer=>[200]}, "$vol?source=tree/a&dest=tree/x";
# List  'tree/' recursively
test_get 'listing all \'tree/\' files', authed_only(200, 'application/json'), "$vol?filter=tree/&recursive", undef,
    sub {
        my $json_raw = shift;
        my $json = get_json($json_raw) or return 0;
        return 0 unless is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 5;
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/x/\a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/x/?*\\'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/x'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/d'});
    };

test_get 'listing files matching pattern \'[ad]\'', authed_only(200, 'application/json'), "$vol?filter=[ad]&recursive", undef,
    sub {
        my $json_raw = shift;
        my $json = get_json($json_raw) or return 0;
        return 0 unless is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 0;
    };

test_put_job "mass rename on $vol (non-recursively rename /tree/x to /tree/c)", {'badauth'=>[401],$reader=>[403],$writer=>[200]}, "$vol?source=tree/x&dest=tree/c";
# Check correctness of non-recursive rename, x/* should be left intact
test_get 'listing all \'tree/\' files', authed_only(200, 'application/json'), "$vol?filter=tree/&recursive", undef,
    sub {
        my $json_raw = shift;
        my $json = get_json($json_raw) or return 0;
        return 0 unless is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 5;
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/x/\a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/x/?*\\'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/c'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/d'});
    };

test_put_job "mass rename on $vol (non-recursively rename /tree/c to /tree/c)", {'badauth'=>[401],$reader=>[403],$writer=>[200]}, "$vol?source=tree/c&dest=tree/c";
test_put_job "mass rename on $vol (recursively rename /tree/x to /tree/x)", {'badauth'=>[401],$reader=>[403],$writer=>[200]}, "$vol?source=tree/x/&dest=tree/x/&recursive";
# Check correctness of renaming files /tree/x/* and /tree/c to itself (those files should be skipped and all should be left untouched)
test_get 'listing all \'tree/\' files', authed_only(200, 'application/json'), "$vol?filter=tree/&recursive", undef,
    sub {
        my $json_raw = shift;
        my $json = get_json($json_raw) or return 0;
        return 0 unless is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 5;
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/x/\a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/x/?*\\'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/c'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/d'});
    };

test_put_job "mass rename on $vol (move /tree/c to /tree/a/ subdir)", {'badauth'=>[401],$reader=>[403],$writer=>[200]}, "$vol?source=tree/c&dest=tree/a/a";
test_put_job "mass rename on $vol (move /tree/d to /tree/a)", {'badauth'=>[401],$reader=>[403],$writer=>[200]}, "$vol?source=tree/d&dest=tree/a";
test_put_job "mass rename on $vol (move /tree/a to /tree/b recursively)", {'badauth'=>[401],$reader=>[403],$writer=>[200]}, "$vol?source=tree/a&dest=tree/b&recursive";
# Check correctness of renaming more than one file and substitution up to the firs slash in the filename suffix
test_get 'listing all \'tree/\' files', authed_only(200, 'application/json'), "$vol?filter=tree/&recursive", undef,
    sub {
        my $json_raw = shift;
        my $json = get_json($json_raw) or return 0;
        return 0 unless is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 5;
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/x/\a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/x/?*\\'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/b/a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/b'});
    };
















my $randname = random_string(1020);
test_upload 'file upload (long file name)', $writer, '', $vol, "abc/".$randname;
test_get 'file with long name existence', authed_only(200, 'application/json'), "$vol?filter=abc/$randname", undef, sub { my $json_raw = shift; my $json = get_json($json_raw) or return 0; return 0 unless is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 1; };
# Rename /abc to /abcd should fail since there is a file with too long name 
test_put_job "mass rename on $vol (rename /abc to /abcd)", {'badauth'=>[401],$reader=>[403],$writer=>[200]}, "$vol?source=abc/&dest=abcd/", undef, 'ERROR';
# Check if the file still exists and pick also the current volume usage
my $curvolsize;
test_get 'file with long name existence (should exist after failed mass rename)', authed_only(200, 'application/json'), "$vol?filter=abc/$randname", undef, sub { my $json_raw = shift; my $json = get_json($json_raw) or return 0; return 0 unless is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 1; $curvolsize = $json->{'volumeUsedSize'}; };
# Now curvolsize should contain current volume usage
# Rename /abc to /a
test_put_job "mass rename on $vol (rename /abc to /a)", {'badauth'=>[401],$reader=>[403],$writer=>[200]}, "$vol?source=abc/&dest=a/";
# Check the volume usage now (should be 2 bytes less)
test_get "$vol volume usage", authed_only(200, 'application/json'), "$vol?filter=a/$randname", undef, sub { my $json_raw = shift; my $json = get_json($json_raw) or return 0; return 0 unless is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 1; $curvolsize == $json->{'volumeUsedSize'} + 2; };




### Check volume modification request ###
test_delete_job "Wiping tiny$vol contents", {'badauth'=>[401],$reader=>[403],$writer=>[200]}, "tiny$vol/toobig";
# Check if volume usage is computed correctly
test_get "$writer quota usage", {$writer=>[200,'application/json']}, ".self", undef, sub { my $json_raw = shift; my $json = get_json($json_raw) or return 0; return is_hash($json->{$writer}) && is_int($json->{$writer}->{'userQuota'}) && $json->{$writer}->{'userQuota'} == 0 && is_int($json->{$writer}->{'userQuotaUsed'}) && $json->{$writer}->{'userQuotaUsed'} == length('empty'); };
test_upload 'file upload (add first revision)', $writer, random_data($tinyvolumesize/2-length('toobig')), "tiny$vol", 'toobig';
test_upload 'file upload (overwrite existing revision)', $writer, random_data($tinyvolumesize/2-length('toobig')), "tiny$vol", 'toobig';
test_get 'file revisions (should be 1)', authed_only(200, 'application/json'), "tiny$vol/toobig?fileRevisions", undef, sub { my $json = get_json(shift); return 0 unless is_hash($json->{'fileRevisions'}) && scalar keys %{$json->{'fileRevisions'}} == 1; };
# Check if volume usage is computed correctly
test_get "$writer quota usage", {$writer=>[200,'application/json']}, ".self", undef, sub { my $json_raw = shift; my $json = get_json($json_raw) or return 0; return is_hash($json->{$writer}) && is_int($json->{$writer}->{'userQuota'}) && $json->{$writer}->{'userQuota'} == 0 && is_int($json->{$writer}->{'userQuotaUsed'}) && $json->{$writer}->{'userQuotaUsed'} == length('empty') + $tinyvolumesize/2; };
test_put_job "Increasing max revisions for tiny$vol", {$writer=>[200]}, "tiny$vol?o=mod", "{\"maxRevisions\":2}";
test_get "tiny$vol max revisions limit modification", {'badauth'=>[401],$reader=>[200,'application/json'],$writer=>[200,'application/json'],'admin'=>[200,'application/json']}, "?volumeList", undef, sub { my $json = get_json(shift); return 0 unless is_hash($json->{'volumeList'}) && is_hash($json->{'volumeList'}->{"tiny$vol"}) && is_int($json->{'volumeList'}->{"tiny$vol"}->{'maxRevisions'}) && $json->{'volumeList'}->{"tiny$vol"}->{'maxRevisions'} == 2; };
test_put_job "Increasing max revisions for tiny$vol (too high)", {$writer=>[400]}, "tiny$vol?o=mod", "{\"maxRevisions\":100}"; # Revisions limit is too high
test_upload 'file upload (add new revision)', $writer, random_data($tinyvolumesize/2-length('toobig')), "tiny$vol", 'toobig';
test_get 'file revisions (should be 2)', authed_only(200, 'application/json'), "tiny$vol/toobig?fileRevisions", undef, sub { my $json = get_json(shift); return 0 unless is_hash($json->{'fileRevisions'}) && scalar keys %{$json->{'fileRevisions'}} == 2; };
# Check if volume usage is computed correctly
test_get "$writer quota usage", {$writer=>[200,'application/json']}, ".self", undef, sub { my $json_raw = shift; my $json = get_json($json_raw) or return 0; return is_hash($json->{$writer}) && is_int($json->{$writer}->{'userQuota'}) && $json->{$writer}->{'userQuota'} == 0 && is_int($json->{$writer}->{'userQuotaUsed'}) && $json->{$writer}->{'userQuotaUsed'} == length('empty') + $tinyvolumesize; };
test_put_job "Decreasing max revisions for tiny$vol", {$writer=>[200]}, "tiny$vol?o=mod", "{\"maxRevisions\":1}"; # New revisions limit is lower than current one
test_upload 'file upload (overwrite existing revision)', $writer, random_data($tinyvolumesize/2-length('toobig')), "tiny$vol", 'toobig'; # This will allow server to finish delete jobs
test_get 'file revisions (should be 1)', authed_only(200, 'application/json'), "tiny$vol/toobig?fileRevisions", undef, sub { my $json = get_json(shift); return 0 unless is_hash($json->{'fileRevisions'}) && scalar keys %{$json->{'fileRevisions'}} == 1; };
test_get "tiny$vol volume meta (empty)", {'admin'=>[200,'application/json'],'badauth'=>[401],$reader=>[200,'application/json'],$writer=>[200,'application/json']}, "?volumeList&customVolumeMeta", undef, sub { my $json = get_json(shift) or return 0; return is_hash($json->{"volumeList"}) && is_hash($json->{"volumeList"}->{"tiny$vol"}) && is_hash($json->{"volumeList"}->{"tiny$vol"}->{'customVolumeMeta'}) && keys %{$json->{"tiny$vol"}->{'customVolumeMeta'}} == 0 };
test_put_job "custom tiny$vol volume meta setting", {'admin'=>[200,'application/json']}, "tiny$vol?o=mod", "{\"customVolumeMeta\":{\"customMetaKey1\":\"aabbcc\",\"customMetaKey2\":\"123456abcd\"}}";
test_get "tiny$vol volume meta (two custom values)", {'admin'=>[200,'application/json'],'badauth'=>[401],$reader=>[200,'application/json'],$writer=>[200,'application/json']}, "?volumeList&customVolumeMeta", undef, sub { my $json = get_json(shift) or return 0; return is_hash($json->{"volumeList"}) && is_hash($json->{"volumeList"}->{"tiny$vol"}) && is_hash($json->{"volumeList"}->{"tiny$vol"}->{'customVolumeMeta'}) && keys %{$json->{"volumeList"}->{"tiny$vol"}->{'customVolumeMeta'}} == 2 && ($json->{"volumeList"}->{"tiny$vol"}->{'customVolumeMeta'}->{'customMetaKey1'} eq 'aabbcc') && ($json->{"volumeList"}->{"tiny$vol"}->{'customVolumeMeta'}->{'customMetaKey2'} eq '123456abcd'); };
test_upload 'file upload (overwrite existing revision)', $writer, random_data($tinyvolumesize-length('toobig')), "tiny$vol", 'toobig'; # Should fit exactly into volume capacity
# Check if volume usage is computed correctly
test_get "$writer quota usage", {$writer=>[200,'application/json']}, ".self", undef, sub { my $json_raw = shift; my $json = get_json($json_raw) or return 0; return is_hash($json->{$writer}) && is_int($json->{$writer}->{'userQuota'}) && $json->{$writer}->{'userQuota'} == 0 && is_int($json->{$writer}->{'userQuotaUsed'}) && $json->{$writer}->{'userQuotaUsed'} == length('empty') + $tinyvolumesize; };
# Try setting custom meta values on a volume with existing, non-custom meta
test_put_job "custom meta.$vol volume meta setting", {'admin'=>[200,'application/json']}, "meta.$vol?o=mod", "{\"customVolumeMeta\":{\"customMetaKey1\":\"aabbccdefa\"}}";
# Setting custom volume meta should not influence existing values
test_get "meta.$vol volume meta (non-empty, one custom value)", {'badauth'=>[401],$reader=>[200,'application/json'],$writer=>[200,'application/json'],'admin'=>[200,'application/json']}, "?volumeList&volumeMeta&customVolumeMeta", undef, sub { my $json = get_json(shift) or return 0; if(!(is_hash($json->{'volumeList'}) && is_hash($json->{'volumeList'}->{"meta.$vol"}))) { return 0; } my $meta = $json->{'volumeList'}->{"meta.$vol"}->{'volumeMeta'}; my $cmeta = $json->{'volumeList'}->{"meta.$vol"}->{'customVolumeMeta'}; return is_hash($meta) && (scalar keys %{$meta} == 3) && (scalar keys %{$cmeta} == 1) && $meta->{'one'} eq '01' && $meta->{'two'} eq '2222' && $meta->{'three'} eq '333333' && ($cmeta->{'customMetaKey1'} eq 'aabbccdefa'); };
# Take out previously assigned custom meta value
test_put_job "custom meta.$vol volume meta setting", {'admin'=>[200,'application/json']}, "meta.$vol?o=mod", "{\"customVolumeMeta\":{}}";
# Check if old meta values were preserved correctly
test_get "meta.$vol volume meta (non-empty)", {'badauth'=>[401],$reader=>[200,'application/json'],$writer=>[200,'application/json'],'admin'=>[200,'application/json']}, "?volumeList&volumeMeta", undef, sub { my $json = get_json(shift) or return 0; if(!(is_hash($json->{'volumeList'}) && is_hash($json->{'volumeList'}->{"meta.$vol"}))) { return 0; } my $meta = $json->{'volumeList'}->{"meta.$vol"}->{'volumeMeta'}; my $cmeta = $json->{'volumeList'}->{"meta.$vol"}->{'customVolumeMeta'}; return is_hash($meta) && (scalar keys %{$meta} == 3) && (scalar keys %{$cmeta} == 0) && $meta->{'one'} eq '01' && $meta->{'two'} eq '2222' && $meta->{'three'} eq '333333'; };
# Setting custom meta together with other values like volume size or owner should only be allowed for an admin user
test_put_job "custom tiny$vol volume meta and size setting", {'badauth'=>[401],$reader=>[403],$writer=>[403]}, "tiny$vol?o=mod", "{\"customVolumeMeta\":{\"customMetaKey1\":\"aabbcc\",\"customMetaKey2\":\"123456abcd\"},\"size\":$tinyvolumesize}";
test_put_job "custom tiny$vol volume meta and revisions limit setting", {'badauth'=>[401],$reader=>[403]}, "tiny$vol?o=mod", "{\"customVolumeMeta\":{\"customMetaKey1\":\"aabbcc\",\"customMetaKey2\":\"123456abcd\"},\"maxRevisions\":2}";
test_put_job "custom tiny$vol volume meta and owner setting", {'badauth'=>[401],$reader=>[403],$writer=>[403]}, "tiny$vol?o=mod", "{\"customVolumeMeta\":{\"customMetaKey1\":\"aabbcc\",\"customMetaKey2\":\"123456abcd\"},\"owner\":\"$reader\"}";
# Creating volume with meta key that uses the reserved prefix should fail
test_mkvol "volume creation (tiny volume with invalid meta)", admin_only(400), "badtiny$vol", "{\"volumeSize\":$tinyvolumesize,\"owner\":\"admin\",\"volumeMeta\":{\"\$custom\$\":\"00\"}}";
test_put_job "owner quota change for $writer", admin_only(200), ".users/$writer", "{\"quota\":0}";

my $oldsize = $tinyvolumesize;
$tinyvolumesize = $tinyvolumesize + 2;
test_put_job "Increasing tiny$vol volume size", admin_only(200), "tiny$vol?o=mod", "{\"size\":$tinyvolumesize}"; # Without this change call below should return 413
test_upload 'bigger file upload (overwrite existing revision)', $writer, random_data($oldsize-length('toobig')+1), "tiny$vol", 'toobig';
test_put_job "tiny$vol ownership change (invalid owner)", admin_only(404), "tiny$vol?o=mod", "{\"owner\":\"somebadusername\"}";
test_put_job "tiny$vol ownership change ($reader)", admin_only(200), "tiny$vol?o=mod", "{\"owner\":\"$reader\"}";
test_get 'volume ownership', {$reader=>[200,'application/json']}, "tiny$vol?o=acl&manager", undef, sub { my $json = get_json(shift); my %is_priv = map { $_, 1 } @{$json->{$reader}}; return is_array($json->{$reader}) && $is_priv{'owner'}; };
test_put_job "tiny$vol ownership change (admin)", admin_only(200), "tiny$vol?o=mod", "{\"owner\":\"admin\"}";
test_get 'volume ownership', {'admin'=>[200,'application/json']}, "tiny$vol?o=acl&manager", undef, sub { my $json = get_json(shift); my %is_priv = map { $_, 1 } @{$json->{'admin'}}; return is_array($json->{'admin'}) && $is_priv{'owner'}; };

test_get "listing tiny$vol files", admin_only(200, 'application/json'), "tiny$vol?filter=*", undef, sub { my $json_raw = shift; my $json = get_json($json_raw) or return 0; return 0 unless is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 1; return 0 unless is_hash($json->{'fileList'}->{'/toobig'}); };
test_put_job "tiny$vol rename to different$vol", admin_only(200), "tiny$vol?o=mod", "{\"name\":\"different$vol\"}";
test_get "listing different$vol files", admin_only(200, 'application/json'), "different$vol?filter=*", undef, sub { my $json_raw = shift; my $json = get_json($json_raw) or return 0; return 0 unless is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 1; return 0 unless is_hash($json->{'fileList'}->{'/toobig'}); };
# All authed users will get 404 because volume existence check is performed before privileges check
test_get "listing tiny$vol files", authed_only(404), "tiny$vol?filter=*", undef, undef;
test_put_job "different$vol rename back to tiny$vol", admin_only(200), "different$vol?o=mod", "{\"name\":\"tiny$vol\"}";
test_get "listing tiny$vol files", admin_only(200, 'application/json'), "tiny$vol?filter=*", undef, sub { my $json_raw = shift; my $json = get_json($json_raw) or return 0; return 0 unless is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 1; return 0 unless is_hash($json->{'fileList'}->{'/toobig'}); };
test_get "listing different$vol files", authed_only(404), "different$vol?filter=*", undef, undef;
test_put_job "tiny$vol rename to $vol (already exists)", admin_only(409), "tiny$vol?o=mod", "{\"name\":\"$vol\"}";
# All authed users will get 400 due to the error being checked during request content parsing
test_put_job "tiny$vol rename to $vol (too long name)", authed_only(400), "tiny$vol?o=mod", "{\"name\":\"".random_string(256)."\"}";
test_put_job "tiny$vol rename to $vol (too short name)", authed_only(400), "tiny$vol?o=mod", "{\"name\":\"x\"}";




test_get 'listing all volumes', {'badauth'=>[401],$reader=>[200,'application/json'],$writer=>[200,'application/json'],'admin'=>[200,'application/json']}, '?volumeList', undef,
    sub {
        my $json_raw = shift;
        my $who = shift;
        my $json = get_json($json_raw) or return 0 ;
        return 0 unless is_hash($json->{'volumeList'});
        {
            my %lookup = map { $_, 0 } ($vol, "another.$vol", "large$vol", $utfvol);
            foreach(keys %{$json->{'volumeList'}}) {
                return 0 unless is_hash($json->{'volumeList'}->{$_}) && defined $json->{'volumeList'}->{$_}->{'sizeBytes'} && defined $json->{'volumeList'}->{$_}->{'replicaCount'}; delete $lookup{$_}
            }
            return keys %lookup == 0;
        }
    };


test_get 'meta get - empty on create', authed_only(200, 'application/json'), "$vol/1bs+1?fileMeta", undef, sub { my $json = get_json(shift) or return 0; return is_hash($json->{'fileMeta'}) && keys %{$json->{'fileMeta'}} == 0 };
test_get 'meta get - set on create', authed_only(200, 'application/json'), "$vol/0.5bs?fileMeta", undef, sub { my $json = get_json(shift) or return 0; return is_hash($json->{'fileMeta'}) && keys %{$json->{'fileMeta'}} == 2 && ($json->{'fileMeta'}->{'key1'} eq '6669727374') && ($json->{'fileMeta'}->{'key2'} eq '7365636f6e64'); };

test_get 'get revisions', authed_only(200, 'application/json'), "$vol/1bs?fileRevisions", undef, sub { my $json = get_json(shift) or return 0; return 0 unless is_hash($json->{'fileRevisions'}) && keys %{$json->{'fileRevisions'}} == 1; my $r = $json->{'fileRevisions'}{(keys %{$json->{'fileRevisions'}})[0]}; return $r->{'blockSize'} == 4096 && $r->{'fileSize'} == 4096 && is_int($r->{'createdAt'}); };

test_delete_job "delete file as writer", {'badauth'=>[401],$reader=>[403],$writer=>[200]}, "$vol/file";
test_get 'checking deleted file', authed_only(200, 'application/json'), "$vol?filter=file", undef, sub { my $json = get_json(shift) or return 0; return is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 1 };
test_delete_job "delete file as admin", {'badauth'=>[401],$reader=>[403],'admin'=>[200]}, "$vol/file/file";
test_get 'checking deleted file', authed_only(200, 'application/json'), "$vol?filter=file", undef, sub { my $json = get_json(shift) or return 0; return is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 0 };
test_delete_job "delete file again", {$writer=>[404]}, "$vol/file";
test_delete_job "delete file again #2", {$writer=>[404]}, "$vol/file/file";


# Volume deletion
test_delete_job "volume deletion (nonempty)", admin_only(409), "$vol";
test_delete_job "volume deletion", admin_only(200), "another.$vol";
test_get 'deletion effect (via file list)', authed_only(404), "another.$vol";
test_get 'deletion effect (via volume list)', {'badauth'=>[401],$reader=>[200,'application/json'],$writer=>[200,'application/json'],'admin'=>[200,'application/json']}, '?volumeList', undef, sub { my $json = get_json(shift) or return 0; return is_hash($json->{'volumeList'}) && exists($json->{'volumeList'}->{$vol}) && !exists($json->{'volumeList'}->{"another.$vol"}); };


### Users cloning tests ###
my $ru = "reader" . (random_string 32);
my $wu = "writer" . (random_string 32);
my $wc = $wu.'.clone';
my $rc = $ru.'.clone';
my $rcid = ""; # ID of reader user clone that needs to be saved inside authorization token 
my $wcid = ""; # ID of writer user clone that needs to be saved inside authorization token 
my $content;

test_create_user $ru;
test_create_user $wu;
test_create_user $rc, { 'existingName' => $ru };
test_create_user $wc, { 'existingName' => $wu };

test_get "$rc ID", admin_only(200, 'application/json'), ".users/$rc", undef, sub { my $json = get_json(shift) or return 0; return 0 unless is_string($json->{'userID'}); $rcid = $json->{'userID'}; };
test_get "$wc ID", admin_only(200, 'application/json'), ".users/$wc", undef, sub { my $json = get_json(shift) or return 0; return 0 unless is_string($json->{'userID'}); $wcid = $json->{'userID'}; };
fail 'Invalid user ID' unless $rcid ne "" && $wcid ne "";
$TOK{$rc} = encode_base64(hex_to_bin($rcid) . substr(decode_base64($TOK{$rc}), 20));
$TOK{$wc} = encode_base64(hex_to_bin($wcid) . substr(decode_base64($TOK{$wc}), 20));

test_mkvol "volume creation (clones' volume)", admin_only(200), "clones$vol", "{\"volumeSize\":$tinyvolumesize,\"owner\":\"$wu\"}";
test_put_job 'granting rights on newly created volume', {$wc=>[200],'badauth'=>[401],$rc=>[403],$wu=>[200],$ru=>[403],'admin'=>[200]}, "clones$vol?o=acl", "{\"grant-read\":[\"$ru\",\"$wu\"],\"grant-write\":[\"$wu\"] }";
test_get 'the newly created volume ownership', {'badauth'=>[401],$wu=>[200,'application/json'],'admin'=>[200,'application/json'],$wc=>[200,'application/json']}, "clones$vol?o=acl&manager", undef, sub { my $json = get_json(shift) or return 0; return is_array($json->{$wu}) && @{$json->{$wu}} == 4 && is_array($json->{$ru}) && @{$json->{$ru}} == 1 && is_array($json->{$wc}) && @{$json->{$wc}} == 4 };

test_upload 'file upload (empty file)', $wc, '', "clones$vol", 'empty.clone';
test_get 'listing as cloned users too', {'badauth'=>[401],$ru=>[200,'application/json'],$wu=>[200,'application/json'],'admin'=>[200,'application/json'],$rc=>[200,'application/json'],$wc=>[200,'application/json']},
    "clones$vol?filter=empty.clone", undef, sub { my $json = get_json(shift) or return 0; return is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 1 && is_hash($json->{'fileList'}->{'/empty.clone'}) };

test_delete_job "$wu.clone deletion", admin_only(200), ".users/$wc";
test_upload 'file upload (empty file) again', $wu, '', "clones$vol", 'empty.clone';
test_get 'listing as cloned users too', {'badauth'=>[401],$ru=>[200,'application/json'],$wu=>[200,'application/json'],'admin'=>[200,'application/json'],$rc=>[200,'application/json'],$wc=>[401]},
    "clones$vol?filter=empty.clone", undef, sub { my $json = get_json(shift) or return 0; return is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 1 && is_hash($json->{'fileList'}->{'/empty.clone'}) };

test_get 'if volume is still owned by $wu', {$wu=>[200, 'application/json'],'admin'=>[200, 'application/json']}, "clones$vol?o=acl&manager", undef, sub { my $json = get_json(shift) or return 0; return is_array($json->{$wu}) && @{$json->{$wu}} == 4; };
test_delete_job "$wu deletion", {'admin'=>[200, 'application/json']}, ".users/$wu";
test_get 'if volume is no longer owned by $wu', {'admin'=>[200, 'application/json']}, "clones$vol?o=acl&manager", undef, sub { my $json = get_json(shift) or return 0; return !is_array($json->{$wu}) && is_array($json->{'admin'}) && @{$json->{'admin'}} == 4; };
test_get 'listing as cloned users too', {'badauth'=>[401],$ru=>[200,'application/json'],$wu=>[401],'admin'=>[200,'application/json'],$rc=>[200,'application/json'],$wc=>[401]},
        "clones$vol?filter=empty.clone", undef, sub { my $json = get_json(shift) or return 0; return is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 1 && is_hash($json->{'fileList'}->{'/empty.clone'}) };

# Check listing users by ID
test_get "listing clones of $ru", admin_only(200, 'application/json'), ".users?clones=$ru", undef, sub { my $json = get_json(shift) or return 0; return scalar keys %{$json} == 2 && is_hash($json->{$ru}) && is_hash($json->{$rc}) };

test_delete_job "$rc deletion with all its clones", admin_only(200), ".users/$rc?all";
test_get "checking if $ru was also deleted", admin_only(404), ".users/$ru";

# Check listing users by ID ($ru was removed, this should not return any user)
test_get "listing clones of $ru", admin_only(404), ".users?clones=$ru";





### User meta tests ###
my $mu = "meta" . (random_string 32);
my $mcu = "meta-clone" . (random_string 32);
my $mcuid;

# Create regular users with and without metadata
test_create_user $mu, { 'userMeta' => { } };
test_get "checking $mu ID", admin_only(200, 'application/json'), ".users/$mu", undef, sub { my $json = get_json(shift) or return 0; return 0 unless is_string($json->{'userID'}) && !is_hash($json->{'userMeta'}); };
test_get "checking $mu ID (obtaining user meta)", admin_only(200, 'application/json'), ".users/$mu?userMeta", undef, sub { my $json = get_json(shift) or return 0; return 0 unless is_string($json->{'userID'}) && is_hash($json->{'userMeta'}) && scalar keys %{$json->{'userMeta'}} == 0;};
test_get "getting $mu user info", { $mu => [200, 'application/json'] }, ".self", undef, sub { my $json = get_json(shift) or return 0; return 0 unless is_hash($json->{$mu}); return 1 unless is_hash($json->{$mu}->{'userMeta'}) || is_hash($json->{$mu}->{'customUserMeta'}); };
test_get "getting $mu user info with metadata", { $mu => [200, 'application/json'] }, ".self?userMeta", undef, sub { my $json = get_json(shift) or return 0; return 0 unless is_hash($json->{$mu}); return 0 unless is_hash($json->{$mu}->{'userMeta'}); return scalar keys %{$json->{$mu}->{'userMeta'}} == 0};
test_delete_job "$mu deletion", admin_only(200), ".users/$mu";
test_create_user $mu, {'userMeta' => { 'key1' => 'aabbcc', 'key2' => '12345678'}};
test_get "checking $mu ID (obtaining user meta)", admin_only(200, 'application/json'), ".users/$mu?userMeta", undef, sub { my $json = get_json(shift) or return 0; return 0 unless is_string($json->{'userID'}) && is_hash($json->{'userMeta'}); return scalar keys %{$json->{'userMeta'}} == 2 && $json->{'userMeta'}->{'key1'} eq 'aabbcc' && $json->{'userMeta'}->{'key2'} eq '12345678'; };
test_get "getting $mu user info", { $mu => [200, 'application/json'] }, ".self", undef, sub { my $json = get_json(shift) or return 0; return 1 unless is_hash($json->{$mu}->{'userMeta'}) || is_hash($json->{$mu}->{'customUserMeta'}); };
test_get "getting $mu user info with metadata", { $mu => [200, 'application/json'] }, ".self?userMeta", undef, sub { my $json = get_json(shift) or return 0; return 0 unless is_hash($json->{$mu}); my $meta = $json->{$mu}->{'userMeta'}; return 0 unless is_hash($meta); return 0 unless scalar keys %{$meta} == 2 && $meta->{'key1'} eq 'aabbcc' && $meta->{'key2'} eq '12345678'; };

# Clones should have their own metadata
test_create_user $mcu, { 'existingName' => $mu, 'userMeta' => { } };
test_get "checking $mcu ID", admin_only(200, 'application/json'), ".users/$mcu", undef, sub { my $json = get_json(shift) or return 0; return 0 unless is_string($json->{'userID'}); $mcuid = $json->{'userID'}; };
$TOK{$mcu} = encode_base64(hex_to_bin($mcuid) . substr(decode_base64($TOK{$mcu}), 20));
test_get "getting $mcu user info (1)", { $mcu => [200, 'application/json'] }, ".self", undef, sub { my $json = get_json(shift) or return 0; return 0 unless is_hash($json->{$mcu}); return 1 unless is_hash($json->{$mcu}->{'userMeta'}) || is_hash($json->{$mcu}->{'customUserMeta'}); };
test_get "getting $mcu user info with metadata", { $mcu => [200, 'application/json'] }, ".self?userMeta", undef, sub { my $json = get_json(shift) or return 0; return 0 unless is_hash($json->{$mcu}); return 0 unless is_hash($json->{$mcu}->{'userMeta'}); return scalar keys %{$json->{$mcu}->{'userMeta'}} == 0};
test_delete_job "$mcu deletion", admin_only(200), ".users/$mcu";
test_create_user $mcu, { 'existingName' => $mu, 'userMeta' => { 'a' => 'aabbee', 'b' => '0012345678', 'c' => '' } };
test_get "checking $mcu ID", admin_only(200, 'application/json'), ".users/$mcu", undef, sub { my $json = get_json(shift) or return 0; return 0 unless is_string($json->{'userID'}); $mcuid = $json->{'userID'}; };
$TOK{$mcu} = encode_base64(hex_to_bin($mcuid) . substr(decode_base64($TOK{$mcu}), 20));
test_get "getting $mcu user info (2)", { $mcu => [200, 'application/json'] }, ".self", undef, sub { my $json = get_json(shift) or return 0; return 0 unless is_hash($json->{$mcu}); return 1 unless is_hash($json->{$mcu}->{'userMeta'}) || is_hash($json->{$mcu}->{'customUserMeta'}); };
test_get "getting $mcu user info with metadata", { $mcu => [200, 'application/json'] }, ".self?userMeta", undef, sub { my $json = get_json(shift) or return 0; return 0 unless is_hash($json->{$mcu}); my $meta = $json->{$mcu}->{'userMeta'}; return 0 unless is_hash($meta); return 0 unless scalar keys %{$meta} == 3 && $meta->{'a'} eq 'aabbee' && $meta->{'b'} eq '0012345678' && $meta->{'c'} eq ''; };

# Custom user meta modification tests
test_get "getting $mu user info with metadata", { $mu => [200, 'application/json'] }, ".self?customUserMeta&userMeta", undef, sub { my $json = get_json(shift) or return 0; return 0 unless is_hash($json->{$mu}); my $meta = $json->{$mu}->{'userMeta'}; my $cmeta = $json->{$mu}->{'customUserMeta'}; return 0 unless is_hash($meta); return 0 unless is_hash($cmeta); return 0 unless scalar keys %{$meta} == 2 && scalar keys %{$cmeta} == 0 && $meta->{'key1'} eq 'aabbcc' && $meta->{'key2'} eq '12345678'; };
test_get "getting $mcu user info with metadata", { $mcu => [200, 'application/json'] }, ".self?customUserMeta&userMeta", undef, sub { my $json = get_json(shift) or return 0; return 0 unless is_hash($json->{$mcu}); my $meta = $json->{$mcu}->{'userMeta'}; my $cmeta = $json->{$mcu}->{'customUserMeta'}; return 0 unless is_hash($meta); return 0 unless is_hash($cmeta); return 0 unless scalar keys %{$meta} == 3 && scalar keys %{$cmeta} == 0 && $meta->{'a'} eq 'aabbee' && $meta->{'b'} eq '0012345678' && $meta->{'c'} eq ''; };
test_put_job "setting custom meta for $mu", { $mcu => [403], 'badauth' => [401], $mu => [200, 'application/json'] }, ".users/$mu", "{\"customUserMeta\":{\"x\":\"\"}}";
test_get "getting $mu user info with metadata", { $mu => [200, 'application/json'] }, ".self?customUserMeta&userMeta", undef, sub { my $json = get_json(shift) or return 0; return 0 unless is_hash($json->{$mu}); my $meta = $json->{$mu}->{'userMeta'}; my $cmeta = $json->{$mu}->{'customUserMeta'}; return 0 unless is_hash($meta); return 0 unless is_hash($cmeta); return 0 unless scalar keys %{$meta} == 2 && scalar keys %{$cmeta} == 1 && $meta->{'key1'} eq 'aabbcc' && $meta->{'key2'} eq '12345678' && $cmeta->{'x'} eq ''; };
test_put_job "setting custom meta for $mu", { $mcu => [403], 'badauth' => [401], $mu => [200, 'application/json'] }, ".users/$mu", "{\"customUserMeta\":{}}";
test_get "getting $mu user info with metadata", { $mu => [200, 'application/json'] }, ".self?customUserMeta&userMeta", undef, sub { my $json = get_json(shift) or return 0; return 0 unless is_hash($json->{$mu}); my $meta = $json->{$mu}->{'userMeta'}; my $cmeta = $json->{$mu}->{'customUserMeta'}; return 0 unless is_hash($meta); return 0 unless is_hash($cmeta); return 0 unless scalar keys %{$meta} == 2 && scalar keys %{$cmeta} == 0 && $meta->{'key1'} eq 'aabbcc' && $meta->{'key2'} eq '12345678'; };
test_put_job "setting custom meta for $mcu", { $mu => [403], 'badauth' => [401], $mcu => [200, 'application/json'] }, ".users/$mcu", "{\"customUserMeta\":{\"x\":\"1234\"}}";
test_get "getting $mcu user info with metadata", { $mcu => [200, 'application/json'] }, ".self?customUserMeta&userMeta", undef, sub { my $json = get_json(shift) or return 0; return 0 unless is_hash($json->{$mcu}); my $meta = $json->{$mcu}->{'userMeta'}; my $cmeta = $json->{$mcu}->{'customUserMeta'}; return 0 unless is_hash($meta); return 0 unless is_hash($cmeta); return 0 unless scalar keys %{$meta} == 3 && scalar keys %{$cmeta} == 1 && $meta->{'a'} eq 'aabbee' && $meta->{'b'} eq '0012345678' && $meta->{'c'} eq '' && $cmeta->{'x'} eq '1234'; };
test_put_job "setting quota for $mcu", { $mu => [403], 'badauth' => [401], $mcu => [403], 'admin' => [200] }, ".users/$mcu", "{\"quota\":$tinyvolumesize}";
test_get "getting $mcu user info with metadata (should not be changed)", { $mcu => [200, 'application/json'] }, ".self?customUserMeta&userMeta", undef, sub { my $json = get_json(shift) or return 0; return 0 unless is_hash($json->{$mcu}); my $meta = $json->{$mcu}->{'userMeta'}; my $cmeta = $json->{$mcu}->{'customUserMeta'}; return 0 unless is_hash($meta); return 0 unless is_hash($cmeta); return 0 unless scalar keys %{$meta} == 3 && scalar keys %{$cmeta} == 1 && $meta->{'a'} eq 'aabbee' && $meta->{'b'} eq '0012345678' && $meta->{'c'} eq '' && $cmeta->{'x'} eq '1234'; };
test_get "getting user list with metadata", admin_only(200, 'application/json'), ".users?customUserMeta&userMeta", undef, sub { my $json = get_json(shift) or return 0; return 0 unless is_hash($json->{$mu}); my $meta = $json->{$mu}->{'userMeta'}; my $cmeta = $json->{$mu}->{'customUserMeta'}; return 0 unless is_hash($meta); return 0 unless is_hash($cmeta); return 0 unless scalar keys %{$meta} == 2 && scalar keys %{$cmeta} == 0 && $meta->{'key1'} eq 'aabbcc' && $meta->{'key2'} eq '12345678'; $meta = $json->{$mcu}->{'userMeta'}; $cmeta = $json->{$mcu}->{'customUserMeta'}; return 0 unless is_hash($meta); return 0 unless is_hash($cmeta); return 0 unless scalar keys %{$meta} == 3 && scalar keys %{$cmeta} == 1 && $meta->{'a'} eq 'aabbee' && $meta->{'b'} eq '0012345678' && $meta->{'c'} eq '' && $cmeta->{'x'} eq '1234'; };

# Regular and custom meta limits checks
test_put_job "setting custom meta for $mu (too many keys)", { $mcu => [403], 'badauth' => [401], 'admin'=>[400], $mu => [400, 'application/json'] }, ".users/$mu", "{\"customUserMeta\":{\"1\":\"0a\",\"2\":\"0a\",\"3\":\"0a\",\"4\":\"0a\",\"5\":\"0a\",\"6\":\"0a\",\"7\":\"0a\",\"8\":\"0a\",\"9\":\"0a\",\"10\":\"0a\",\"11\":\"0a\",\"12\":\"0a\",\"13\":\"0a\",\"14\":\"0a\",\"15\":\"0a\",\"16\":\"0a\",\"17\":\"0a\"}}";
test_get "getting $mu user info with metadata", { $mu => [200, 'application/json'] }, ".self?customUserMeta&userMeta", undef, sub { my $json = get_json(shift) or return 0; return 0 unless is_hash($json->{$mu}); return 0 unless is_hash($json->{$mu}->{'userMeta'}); return 0 unless is_hash($json->{$mu}->{'customUserMeta'}); return scalar keys %{$json->{$mu}->{'userMeta'}} == 2 && scalar keys %{$json->{$mu}->{'customUserMeta'}} == 0};
test_put_job "setting custom meta for $mu (maximal number of keys)", { $mcu => [403], 'badauth' => [401], 'admin'=>[200], $mu => [200] }, ".users/$mu", "{\"customUserMeta\":{\"1\":\"0a\",\"2\":\"0a\",\"3\":\"0a\",\"4\":\"0a\",\"5\":\"0a\",\"6\":\"0a\",\"7\":\"0a\",\"8\":\"0a\",\"9\":\"0a\",\"10\":\"0a\",\"11\":\"0a\",\"12\":\"0a\",\"13\":\"0a\",\"14\":\"0a\",\"15\":\"0a\",\"16\":\"0a\"}}";
test_get "getting $mu user info with metadata", { $mu => [200, 'application/json'] }, ".self?customUserMeta&userMeta", undef, sub { my $json = get_json(shift) or return 0; return 0 unless is_hash($json->{$mu}); return 0 unless is_hash($json->{$mu}->{'userMeta'}); return 0 unless is_hash($json->{$mu}->{'customUserMeta'}); return scalar keys %{$json->{$mu}->{'userMeta'}} == 2 && scalar keys %{$json->{$mu}->{'customUserMeta'}} == 16};
test_delete_job "$mu deletion", admin_only(200), ".users/$mu";

my $umetaitems = { map { $_ => "acab" } (0..127) };
test_create_user $mu, { 'userMeta' => $umetaitems };
test_get "checking $mu ID", admin_only(200, 'application/json'), ".users/$mu", undef, sub { my $json = get_json(shift) or return 0; return 0 unless is_string($json->{'userID'}); };
test_get "getting $mu user info with metadata", { $mu => [200, 'application/json'] }, ".self?customUserMeta&userMeta", undef, sub { my $json = get_json(shift) or return 0; return 0 unless is_hash($json->{$mu}); my $meta = $json->{$mu}->{'userMeta'}; my $cmeta = $json->{$mu}->{'customUserMeta'}; return 0 unless is_hash($meta); return 0 unless is_hash($cmeta); return 0 unless scalar keys %{$meta} == 128 && scalar keys %{$cmeta} == 0; };
test_put_job "setting custom meta for $mu (exceeding limit for meta entries)", { $mcu => [403], 'badauth' => [401], $mu => [400] }, ".users/$mu", "{\"customUserMeta\":{\"x\":\"\"}}";
test_delete_job "$mu deletion", admin_only(200), ".users/$mu";
test_put_job "Creating $mu user with metadata (exceeding limit for meta entries)", admin_only(400), '.users', "{ \"userType\":\"normal\", \"userName\":\"$mu\", \"userKey\":\"".bin_to_hex(random_data(20))."\", \"userMeta\":{$metaitems,\"x\":\"a\"} }";
delete $umetaitems->{'127'};
test_create_user $mu, { 'userMeta' => $umetaitems };
test_get "checking $mu ID", admin_only(200, 'application/json'), ".users/$mu", undef, sub { my $json = get_json(shift) or return 0; return 0 unless is_string($json->{'userID'}); };
test_get "getting $mu user info with metadata", { $mu => [200, 'application/json'] }, ".self?customUserMeta&userMeta", undef, sub { my $json = get_json(shift) or return 0; return 0 unless is_hash($json->{$mu}); my $meta = $json->{$mu}->{'userMeta'}; my $cmeta = $json->{$mu}->{'customUserMeta'}; return 0 unless is_hash($meta); return 0 unless is_hash($cmeta); return 0 unless scalar keys %{$meta} == 127 && scalar keys %{$cmeta} == 0; };
test_put_job "setting custom meta for $mu (maximal number of items)", { $mcu => [403], 'badauth' => [401], $mu => [200] }, ".users/$mu", "{\"customUserMeta\":{\"x\":\"\"}}";
test_get "getting $mu user info with metadata", { $mu => [200, 'application/json'] }, ".self?customUserMeta&userMeta", undef, sub { my $json = get_json(shift) or return 0; return 0 unless is_hash($json->{$mu}); my $meta = $json->{$mu}->{'userMeta'}; my $cmeta = $json->{$mu}->{'customUserMeta'}; return 0 unless is_hash($meta); return 0 unless is_hash($cmeta); return 0 unless scalar keys %{$meta} == 127 && scalar keys %{$cmeta} == 1; };
test_put_job "setting custom meta for $mu (exceeding limit for meta entries)", { $mcu => [403], 'badauth' => [401], $mu => [400] }, ".users/$mu", "{\"customUserMeta\":{\"x\":\"\",\"1234\":\"aabbccdd\"}}";
test_put_job "setting custom meta for $mu (exceeding limit for single meta entry)", { $mcu => [403], 'badauth' => [401], $mu => [400] }, ".users/$mu", "{\"customUserMeta\":{\"x\":\"".bin_to_hex(random_string(65537))."\"}}";
test_put_job "setting custom meta for $mu (maximal size of a single meta entry)", { $mcu => [403], 'badauth' => [401], $mu => [200] }, ".users/$mu", "{\"customUserMeta\":{\"x\":\"".bin_to_hex(random_string(65536))."\"}}";
test_get "getting user list with metadata", admin_only(200, 'application/json'), ".users?customUserMeta&userMeta", undef, sub { my $json = get_json(shift) or return 0; return 0 unless is_hash($json->{$mu}); my $meta = $json->{$mu}->{'userMeta'}; my $cmeta = $json->{$mu}->{'customUserMeta'}; return 0 unless is_hash($meta); return 0 unless is_hash($cmeta); return 0 unless scalar keys %{$meta} == 127 && scalar keys %{$cmeta} == 1; };
test_get "getting user list with metadata (custom only)", { 'admin' => [200, 'application/json'] }, ".users?customUserMeta", undef, sub { my $json = get_json(shift) or return 0; return 0 unless is_hash($json->{$mu}); my $cmeta = $json->{$mu}->{'customUserMeta'}; return 0 unless is_hash($cmeta); return 0 unless scalar keys %{$cmeta} == 1; };
test_get "getting user list with metadata (regular only)", { 'admin' => [200, 'application/json'] }, ".users?userMeta", undef, sub { my $json = get_json(shift) or return 0; return 0 unless is_hash($json->{$mu}); my $meta = $json->{$mu}->{'userMeta'}; return 0 unless is_hash($meta); return 0 unless scalar keys %{$meta} == 127; };






# Check if .status query returns node status
test_get "node status", admin_only(200, 'application/json'), ".status", undef, sub { my $json = get_json(shift); return 0 unless is_string($json->{'osType'}) && is_string($json->{'osArch'}) && is_string($json->{'osRelease'})
    && is_string($json->{'osVersion'}) && is_string($json->{'osEndianness'}) && is_string($json->{'libsxclientVersion'}) && is_string($json->{'hashFSVersion'}) && is_string($json->{'localTime'}) && is_string($json->{'utcTime'})
    && is_string($json->{'address'}) && is_string($json->{'internalAddress'}) && is_string($json->{'UUID'}) && is_string($json->{'nodeDir'}) && is_int($json->{'storageAllocated'}) && is_int($json->{'storageUsed'}) && is_int($json->{'fsBlockSize'})
    && is_int($json->{'fsTotalBlocks'}) && is_int($json->{'fsAvailBlocks'}) && (is_int($json->{'memTotal'}) || $json->{'memTotal'} == -1); };


# Check .lock query correctness
test_put_job "distribution lock acquisition", admin_only(200), ".distlock", "{\"op\":\"lock\"}";
test_put_job "distribution lock acquisition (should fail)", admin_only(409), ".distlock", "{\"op\":\"lock\"}";
test_put_job "distribution lock release", admin_only(200), ".distlock", "{\"op\":\"unlock\"}";


# Check switching cluster read-only/read-write modes
test_put_job "switching cluster to read-only mode", {'admin'=>[200]}, ".mode", "{\"mode\":\"ro\"}";
test_upload 'file upload to read-only cluster', $writer, '', "large$vol", 'empty', undef, {}, 503;
test_get 'listing all files (GET should work)', authed_only(200), $vol;
test_put_job "switching cluster back to read-write mode", , {'admin'=>[200]}, ".mode", "{\"mode\":\"rw\"}";
# PUT should work again
test_upload 'file upload to read-write cluster', $writer, '', "large$vol", 'empty';



# Check volume used sizes and files counter
test_delete_job "wiping tiny$vol contents", {'admin'=>[200,'application/json']}, "tiny$vol?filter=*";
test_get "tiny$vol current usage (locate)", {'admin'=>[200,'application/json']}, "?volumeList", undef, sub { my $json = get_json(shift); return 0 unless is_hash($json->{'volumeList'}) && is_hash($json->{'volumeList'}->{"tiny$vol"}) && is_int($json->{'volumeList'}->{"tiny$vol"}->{'usedSize'}) && is_int($json->{'volumeList'}->{"tiny$vol"}->{'filesSize'}) && is_int($json->{'volumeList'}->{"tiny$vol"}->{'filesCount'}) && $json->{'volumeList'}->{"tiny$vol"}->{'usedSize'} == 0 && $json->{'volumeList'}->{"tiny$vol"}->{'filesSize'} == 0 && $json->{'volumeList'}->{"tiny$vol"}->{'filesCount'} == 0; };
test_get "tiny$vol current usage (volume list)", {'admin'=>[200,'application/json']}, "tiny$vol?o=locate", undef, sub { my $json = get_json(shift) or return 0; return is_array($json->{'nodeList'}) && is_int($json->{'usedSize'}) && is_int($json->{'filesSize'}) && is_int($json->{'filesCount'}) && $json->{'usedSize'} == 0 && $json->{'filesSize'} == 0 && $json->{'filesCount'} == 0; };
test_upload 'first file upload', 'admin', '', "tiny$vol", 'file1';
test_get "tiny$vol current usage (locate)", {'admin'=>[200,'application/json']}, "?volumeList", undef, sub { my $json = get_json(shift); return 0 unless is_hash($json->{'volumeList'}) && is_hash($json->{'volumeList'}->{"tiny$vol"}) && is_int($json->{'volumeList'}->{"tiny$vol"}->{'usedSize'}) && is_int($json->{'volumeList'}->{"tiny$vol"}->{'filesSize'}) && is_int($json->{'volumeList'}->{"tiny$vol"}->{'filesCount'}) && $json->{'volumeList'}->{"tiny$vol"}->{'usedSize'} == 5 && $json->{'volumeList'}->{"tiny$vol"}->{'filesSize'} == 0 && $json->{'volumeList'}->{"tiny$vol"}->{'filesCount'} == 1; };
test_get "tiny$vol current usage (volume list)", {'admin'=>[200,'application/json']}, "tiny$vol?o=locate", undef, sub { my $json = get_json(shift) or return 0; return is_array($json->{'nodeList'}) && is_int($json->{'usedSize'}) && is_int($json->{'filesSize'}) && is_int($json->{'filesCount'}) && $json->{'usedSize'} == 5 && $json->{'filesSize'} == 0 && $json->{'filesCount'} == 1; };
test_upload 'second file upload', 'admin', random_data(100), "tiny$vol", 'file2';
test_get "tiny$vol current usage (locate)", {'admin'=>[200,'application/json']}, "?volumeList", undef, sub { my $json = get_json(shift); return 0 unless is_hash($json->{'volumeList'}) && is_hash($json->{'volumeList'}->{"tiny$vol"}) && is_int($json->{'volumeList'}->{"tiny$vol"}->{'usedSize'}) && is_int($json->{'volumeList'}->{"tiny$vol"}->{'filesSize'}) && is_int($json->{'volumeList'}->{"tiny$vol"}->{'filesCount'}) && $json->{'volumeList'}->{"tiny$vol"}->{'usedSize'} == 110 && $json->{'volumeList'}->{"tiny$vol"}->{'filesSize'} == 100 && $json->{'volumeList'}->{"tiny$vol"}->{'filesCount'} == 2; };
test_get "tiny$vol current usage (volume list)", {'admin'=>[200,'application/json']}, "tiny$vol?o=locate", undef, sub { my $json = get_json(shift) or return 0; return is_array($json->{'nodeList'}) && is_int($json->{'usedSize'}) && is_int($json->{'filesSize'}) && is_int($json->{'filesCount'}) && $json->{'usedSize'} == 110 && $json->{'filesSize'} == 100 && $json->{'filesCount'} == 2; };
test_delete_job "removing tiny$vol/file1", {'admin'=>[200,'application/json']}, "tiny$vol/file1";
test_get "tiny$vol current usage (locate)", {'admin'=>[200,'application/json']}, "?volumeList", undef, sub { my $json = get_json(shift); return 0 unless is_hash($json->{'volumeList'}) && is_hash($json->{'volumeList'}->{"tiny$vol"}) && is_int($json->{'volumeList'}->{"tiny$vol"}->{'usedSize'}) && is_int($json->{'volumeList'}->{"tiny$vol"}->{'filesSize'}) && is_int($json->{'volumeList'}->{"tiny$vol"}->{'filesCount'}) && $json->{'volumeList'}->{"tiny$vol"}->{'usedSize'} == 105 && $json->{'volumeList'}->{"tiny$vol"}->{'filesSize'} == 100 && $json->{'volumeList'}->{"tiny$vol"}->{'filesCount'} == 1; };
test_get "tiny$vol current usage (volume list)", {'admin'=>[200,'application/json']}, "tiny$vol?o=locate", undef, sub { my $json = get_json(shift) or return 0; return is_array($json->{'nodeList'}) && is_int($json->{'usedSize'}) && is_int($json->{'filesSize'}) && is_int($json->{'filesCount'}) && $json->{'usedSize'} == 105 && $json->{'filesSize'} == 100 && $json->{'filesCount'} == 1; };
test_put_job "mass rename on tiny$vol (move file2 to file_2)", {'admin'=>[200,'application/json']}, "tiny$vol?source=file2&dest=file_2";
test_get "tiny$vol current usage (locate)", {'admin'=>[200,'application/json']}, "?volumeList", undef, sub { my $json = get_json(shift); return 0 unless is_hash($json->{'volumeList'}) && is_hash($json->{'volumeList'}->{"tiny$vol"}) && is_int($json->{'volumeList'}->{"tiny$vol"}->{'usedSize'}) && is_int($json->{'volumeList'}->{"tiny$vol"}->{'filesSize'}) && is_int($json->{'volumeList'}->{"tiny$vol"}->{'filesCount'}) && $json->{'volumeList'}->{"tiny$vol"}->{'usedSize'} == 106 && $json->{'volumeList'}->{"tiny$vol"}->{'filesSize'} == 100 && $json->{'volumeList'}->{"tiny$vol"}->{'filesCount'} == 1; };
test_get "tiny$vol current usage (volume list)", {'admin'=>[200,'application/json']}, "tiny$vol?o=locate", undef, sub { my $json = get_json(shift) or return 0; return is_array($json->{'nodeList'}) && is_int($json->{'usedSize'}) && is_int($json->{'filesSize'}) && is_int($json->{'filesCount'}) && $json->{'usedSize'} == 106 && $json->{'filesSize'} == 100 && $json->{'filesCount'} == 1; };
test_delete_job "wiping tiny$vol contents", {'admin'=>[200,'application/json']}, "tiny$vol?filter=*";
test_get "tiny$vol current usage (locate)", {'admin'=>[200,'application/json']}, "?volumeList", undef, sub { my $json = get_json(shift); return 0 unless is_hash($json->{'volumeList'}) && is_hash($json->{'volumeList'}->{"tiny$vol"}) && is_int($json->{'volumeList'}->{"tiny$vol"}->{'usedSize'}) && is_int($json->{'volumeList'}->{"tiny$vol"}->{'filesSize'}) && is_int($json->{'volumeList'}->{"tiny$vol"}->{'filesCount'}) && $json->{'volumeList'}->{"tiny$vol"}->{'usedSize'} == 0 && $json->{'volumeList'}->{"tiny$vol"}->{'filesSize'} == 0 && $json->{'volumeList'}->{"tiny$vol"}->{'filesCount'} == 0; };
test_get "tiny$vol current usage (volume list)", {'admin'=>[200,'application/json']}, "tiny$vol?o=locate", undef, sub { my $json = get_json(shift) or return 0; return is_array($json->{'nodeList'}) && is_int($json->{'usedSize'}) && is_int($json->{'filesSize'}) && is_int($json->{'filesCount'}) && $json->{'usedSize'} == 0 && $json->{'filesSize'} == 0 && $json->{'filesCount'} == 0; };



# Check cluster meta operations
test_get "cluster meta (empty)", {'badauth'=>[401],$reader=>[200,'application/json'],$writer=>[200,'application/json'],'admin'=>[200,'application/json']}, "?clusterMeta", undef, sub { my $json = get_json(shift) or return 0; return 0 unless is_hash($json->{'clusterMeta'}); $cleanupm = $json->{'clusterMeta'}; };
if(defined($cleanupm)) {
    $metaitems = join(',', map { qq{"$_":"646f67"} } 0..127);
    test_put_job "cluster meta change (two meta entries)", admin_only(200), ".clusterMeta", "{\"clusterMeta\":{\"key1\":\"656c657068616e74\",\"key2\":\"756e69636f726e\"}}";
    test_get "cluster meta (two entries)", {'badauth'=>[401],$reader=>[200,'application/json'],$writer=>[200,'application/json'],'admin'=>[200,'application/json']}, "?clusterMeta", undef, sub { my $json = get_json(shift) or return 0; return is_hash($json->{'clusterMeta'}) && (scalar keys %{$json->{'clusterMeta'}} == 2) && $json->{'clusterMeta'}->{'key1'} eq '656c657068616e74' && $json->{'clusterMeta'}->{'key2'} eq '756e69636f726e' };
    test_put_job "cluster meta change (one meta entry)", admin_only(200), ".clusterMeta", "{\"clusterMeta\":{\"key3\":\"636174\"}}";
    test_get "cluster meta (one entry)", {'badauth'=>[401],$reader=>[200,'application/json'],$writer=>[200,'application/json'],'admin'=>[200,'application/json']}, "?clusterMeta", undef, sub { my $json = get_json(shift) or return 0; return is_hash($json->{'clusterMeta'}) && (scalar keys %{$json->{'clusterMeta'}} == 1) && $json->{'clusterMeta'}->{'key3'} eq '636174' };
    test_put_job "cluster meta change (max meta entries)", admin_only(200), ".clusterMeta", "{\"clusterMeta\":{$metaitems}}";
    test_get "cluster meta (max entries)", {'badauth'=>[401],$reader=>[200,'application/json'],$writer=>[200,'application/json'],'admin'=>[200,'application/json']}, "?clusterMeta", undef, sub { my $json = get_json(shift) or return 0; return is_hash($json->{'clusterMeta'}) && (scalar keys %{$json->{'clusterMeta'}} == 128) };
    test_put_job "cluster meta change (too many meta entries)", admin_only(400), ".clusterMeta", "{\"clusterMeta\":{$metaitems,\"toomany\":\"6561676c65\"}}";
    test_put_job "cluster meta change (invalid string)", admin_only(400), ".clusterMeta", "{\"clusterMeta\":{\"invalid\":\"acab\"}";
} else {
    printf "Skipped cluster meta tests\n";
}

cleanup;

print "\nTests performed: ".($okies+$fails)." - $fails failed, $okies succeeded\n";
exit ($fails > 0);
