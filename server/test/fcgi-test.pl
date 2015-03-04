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
    print 'FAIL ('.shift().")\n";
    $fails++;
}

sub ok {
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
	print "Checking $test ($_)... ";
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
	return -1;
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
	if(!$json || !is_string($json->{'requestStatus'}) || !is_string($json->{'requestMessage'}) || !defined($json->{'requestId'}) || $json->{'requestId'} != $jobid) {
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

    print "Checking $test ($who)... ";
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
	    $content->{'fileSize'} = $len+0;
	    $content->{'fileMeta'} = $meta if(defined $meta);
	    $req = HTTP::Request->new('PUT', "http://$QUERYHOST/".escape_uri($vol, $fname))
	} else {
	    $content->{'extendSeq'} = $i;
	    $req = HTTP::Request->new('PUT', "http://$QUERYHOST/.upload/$token");
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

	print "Checking $test ($_)... ";

	my $jobid = job_submit $verb, $q, $content, $auth, $exp_st;
	next unless defined($jobid);
	if($jobid == -1) {
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

sub test_create_user {
    my $name = shift;
    my $binu = sha1($name);
    my $bink = random_data(20);
    my $content = { 'userName' => $name, 'userType' => 'normal', => 'userKey' => bin_to_hex($bink) };

    test_put_job "user creation $name...", admin_only(200), '.users', encode_json($content);

    $TOK{$name} = encode_base64($binu . $bink . chr(0) . chr(0));
}

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
# FIXME : properly check nodes and volume lists once they are unstubbed #
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

test_put_job 'volume creation (no content)', admin_only(400), $vol;
test_put_job 'volume creation (bad content)', admin_only(400), $vol, "{\"owner\":\"admin\",\"volumeSize\":$volumesize";
test_put_job 'volume creation (bad volume size - too small)', admin_only(400), $vol, '{"owner":"admin","volumeSize":10}';
test_put_job 'volume creation (bad volume size - too big)', admin_only(400), $vol, "{\"owner\":\"admin\",\"volumeSize\":$bigvolumesize}";
test_put_job 'volume creation (no owner)', admin_only(400), $vol, '{"volumeSize":$volumesize}';
test_put_job 'volume creation (reserved name)', admin_only(403), '.reserved', "{\"owner\":\"admin\",\"volumeSize\":$volumesize}";
test_put_job "volume creation", admin_only(200), $vol, "{\"volumeSize\":$volumesize,\"owner\":\"admin\"}";
test_put_job 'granting rights on newly created volume', admin_only(200), $vol."?o=acl", "{\"grant-read\":[\"$reader\",\"$writer\"],\"grant-write\":[\"$writer\"] }";
test_put_job 'creation of the same volume', admin_only(200), $vol, "{\"owner\":\"admin\",\"volumeSize\":$volumesize}", 1;
test_get 'the newly created volume', authed_only(200, 'application/json'), $vol, undef, sub { my $json = get_json(shift) or return 0; return is_int($json->{'volumeSize'}) && $json->{'volumeSize'} == $volumesize && is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 0 };
test_put_job 'creation of another volume', admin_only(200), "another.$vol", "{\"volumeSize\":$volumesize,\"owner\":\"admin\"}";
test_put_job 'granting rights on newly created volume', admin_only(200), "another.$vol?o=acl", "{\"grant-read\":[\"$reader\",\"$writer\"],\"grant-write\":[\"$writer\"] }";
test_get 'the newly created volume', authed_only(200, 'application/json'), "another.$vol", undef, sub { my $json = get_json(shift) or return 0; return is_int($json->{'volumeSize'}) && $json->{'volumeSize'} == $volumesize && is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 0 };
test_get 'the old volume again', authed_only(200, 'application/json'), "another.$vol", undef, sub { my $json = get_json(shift) or return 0; return is_int($json->{'volumeSize'}) && $json->{'volumeSize'} == $volumesize && is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 0 };
test_put_job 'volume creation (negative replica)', admin_only(400), "large$vol", "{\"owner\":\"admin\",\"replicaCount\":-1,\"volumeSize\":$volumesize}";
test_put_job 'volume creation (replica > nodes)', admin_only(400), "large$vol", "{\"owner\":\"admin\",\"replicaCount\":1000,\"volumeSize\":$tinyvolumesize}", 1;
test_put_job 'volume creation (non default replica)', admin_only(200), "large$vol", "{\"owner\":\"admin\",\"replicaCount\":1,\"volumeSize\":$volumesize}";
test_put_job 'granting rights on newly created volume', admin_only(200), "large$vol?o=acl", "{\"grant-read\":[\"$reader\",\"$writer\"],\"grant-write\":[\"$writer\"] }";

my $nuke = chr(0x2622);
my $utfvol = "$vol$nuke";
test_put_job "volume creation (utf-8)", admin_only(200), escape_uri($utfvol), "{\"owner\":\"admin\",\"volumeSize\":$volumesize}";
test_put_job 'granting rights on newly created volume', admin_only(200), escape_uri($utfvol)."?o=acl", "{\"grant-read\":[\"$reader\",\"$writer\"],\"grant-write\":[\"$writer\"] }";
test_get 'the newly created volume', authed_only(200, 'application/json'), escape_uri($utfvol), undef, sub { my $json = get_json(shift) or return 0; return is_int($json->{'volumeSize'}) && $json->{'volumeSize'} == $volumesize && is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 0 };
test_put_job 'volume creation (with meta)', admin_only(200), "meta.$vol", "{\"owner\":\"admin\",\"volumeSize\":$volumesize,\"volumeMeta\":{\"one\":\"01\",\"two\":\"2222\",\"three\":\"333333\"}}";
test_put_job 'granting rights on newly created volume', admin_only(200), "meta.$vol?o=acl", "{\"grant-read\":[\"$reader\",\"$writer\"],\"grant-write\":[\"$writer\"] }";
test_get 'the newly created volume', authed_only(200, 'application/json'), "meta.$vol?o=locate&volumeMeta", undef, sub { my $json = get_json(shift) or return 0; return is_array($json->{'nodeList'}) && is_hash($json->{'volumeMeta'}) && (scalar keys %{$json->{'volumeMeta'}} == 3) && $json->{'volumeMeta'}->{'one'} eq '01' && $json->{'volumeMeta'}->{'two'} eq '2222' && $json->{'volumeMeta'}->{'three'} eq '333333' };
test_get 'the newly created volume for meta ', {'badauth'=>[401],$reader=>[200,'application/json'],$writer=>[200,'application/json'],'admin'=>[200,'application/json']}, "?volumeList&volumeMeta", undef, sub { my $json = get_json(shift) or return 0; if(!(is_hash($json->{'volumeList'}) && is_hash($json->{'volumeList'}->{"meta.$vol"}))) { return 0; } my $meta = $json->{'volumeList'}->{"meta.$vol"}->{'volumeMeta'}; return is_hash($meta) && (scalar keys %{$meta} == 3) && $meta->{'one'} eq '01' && $meta->{'two'} eq '2222' && $meta->{'three'} eq '333333'; };

test_put_job 'volume creation (with bad meta)', admin_only(400), "badmeta.$vol", "{\"owner\":\"admin\",\"volumeSize\":$volumesize,\"volumeMeta\":{\"badval\":\"0dd\"}}";

# Tiny volume will be used for volume size enforcement tests
test_put_job "volume creation (tiny volume)", admin_only(200), "tiny$vol", "{\"volumeSize\":$tinyvolumesize,\"owner\":\"admin\"}";
test_put_job 'granting rights on newly created volume', admin_only(200), "tiny$vol?o=acl", "{\"grant-read\":[\"$reader\",\"$writer\"],\"grant-write\":[\"$writer\"] }";
test_get 'the newly created volume', authed_only(200, 'application/json'), "tiny$vol", undef, sub { my $json = get_json(shift) or return 0; return is_int($json->{'volumeSize'}) && $json->{'volumeSize'} == $tinyvolumesize && is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 0 };

# Misc volume used to test user deletion and revisions
test_put_job "volume creation (misc volume)", admin_only(200), "misc$vol", "{\"volumeSize\":$tinyvolumesize,\"owner\":\"$delme\",\"replicaCount\":1,\"maxRevisions\":2}";
#FIXME this tests is a workaround due to bb#555
test_get 'checking volume ownership', admin_only(200, 'application/json'), "misc$vol?o=acl", undef, sub { my $json = get_json(shift);
    my %is_priv   = map { $_, 1 } @{$json->{$delme}};
    return is_array($json->{$delme}) && $is_priv{'owner'}; };
test_delete_job "user deletion", admin_only(200), ".users/$delme";
test_get 'checking volume ownership', admin_only(200, 'application/json'), "misc$vol?o=acl", undef, sub { 
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

### Check quota handling ###
# This file should not be allowed to be uploaded because quota will be exceeded by one byte
test_upload 'file upload: (exceeding volume capacity)', $writer, random_data($tinyvolumesize-length('toobig')+1), "tiny$vol", 'toobig', undef, {}, 413;
# Check if quota will be enforced also for file with metadata (-meta value length: 10/2=5, +1 byte to exceed)
test_upload 'file upload (exceeding volume capacity (meta))', $writer, random_data($tinyvolumesize-length('toobig')-length('somemeta')-4), "tiny$vol", 'toobig', undef, {'somemeta'=> "ffaabb0011"}, 413;
# This should return 200
test_upload 'file upload (exceeding volume capacity (meta))', $writer, random_data($tinyvolumesize-length('toobig')-length('somemeta')-5), "tiny$vol", 'toobig', undef, {'somemeta'=> "ffaabb0011"};


test_get 'listing all files', authed_only(200, 'application/json'), $vol, undef, sub { my $json = get_json(shift) or return 0; return is_int($json->{'volumeSize'}) && $json->{'volumeSize'} == $volumesize && is_int($json->{'replicaCount'}) && $json->{'replicaCount'} == 1 && is_hash($json->{'fileList'}) && is_hash($json->{'fileList'}->{'/empty'}) && is_int($json->{'fileList'}->{'/empty'}->{'fileSize'}) && $json->{'fileList'}->{'/empty'}->{'fileSize'} == 0 && is_int($json->{'fileList'}->{'/empty'}->{'blockSize'}) && $json->{'fileList'}->{'/empty'}->{'blockSize'} == 4096 && is_int($json->{'fileList'}->{'/empty'}->{'createdAt'}) && is_string($json->{'fileList'}->{'/empty'}->{'fileRevision'}) };
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
        return 0 unless is_int($json->{'volumeSize'}) && $json->{'volumeSize'} == $volumesize && is_int($json->{'replicaCount'}) &&
            $json->{'replicaCount'} == 1 && is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 2;
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
        return 0 unless is_int($json->{'volumeSize'}) && $json->{'volumeSize'} == $volumesize && is_int($json->{'replicaCount'}) &&
            $json->{'replicaCount'} == 1 && is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 5;
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
        return 0 unless is_int($json->{'volumeSize'}) && $json->{'volumeSize'} == $volumesize && is_int($json->{'replicaCount'}) &&
             $json->{'replicaCount'} == 1 && is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 12;
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
        return 0 unless is_int($json->{'volumeSize'}) && $json->{'volumeSize'} == $volumesize && is_int($json->{'replicaCount'}) &&
             $json->{'replicaCount'} == 1 && is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 3;
        return 0 unless is_hash($json->{'fileList'}->{'/tree/a/'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/b'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/b/'});
    };

# List all files from 'tree/??/' (recursively)
test_get 'listing all \'tree/??/\' files (recursively)', authed_only(200, 'application/json'), "$vol?filter=tree/??/&recursive", undef,
    sub {
        my $json_raw = shift;
        my $json = get_json($json_raw) or return 0;
        return 0 unless is_int($json->{'volumeSize'}) && $json->{'volumeSize'} == $volumesize && is_int($json->{'replicaCount'}) &&
             $json->{'replicaCount'} == 1 && is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 4;
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
        return 0 unless is_int($json->{'volumeSize'}) && $json->{'volumeSize'} == $volumesize && is_int($json->{'replicaCount'}) &&
             $json->{'replicaCount'} == 1 && is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 4;
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
        return 0 unless is_int($json->{'volumeSize'}) && $json->{'volumeSize'} == $volumesize && is_int($json->{'replicaCount'}) &&
             $json->{'replicaCount'} == 1 && is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 2;
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/\a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/\a/'});
    };

# List 'tree/??/\[abc]'' (recursively)
test_get 'listing all \'tree/??/\\[abc]\' files (recursively)', authed_only(200, 'application/json'), "$vol?filter=tree/??/\\\\[abc]&recursive", undef,
    sub {
        my $json_raw = shift;
        my $json = get_json($json_raw) or return 0;
        return 0 unless is_int($json->{'volumeSize'}) && $json->{'volumeSize'} == $volumesize && is_int($json->{'replicaCount'}) &&
             $json->{'replicaCount'} == 1 && is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 2;
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/\a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/\a/a'});
    };

# List 'tree/*/\?'' (recursively)
test_get 'listing all \'tree/*/\\?\' files (recursively)', authed_only(200, 'application/json'), "$vol?filter=tree/*/\\\\?&recursive", undef,
    sub {
        my $json_raw = shift;
        my $json = get_json($json_raw) or return 0;
        return 0 unless is_int($json->{'volumeSize'}) && $json->{'volumeSize'} == $volumesize && is_int($json->{'replicaCount'}) &&
             $json->{'replicaCount'} == 1 && is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 2;
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/\a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/\a/a'});
    };

# List 'tree/*/*\*''
test_get 'listing all \'tree/*/\\*\' files', authed_only(200, 'application/json'), "$vol?filter=tree/*/*\\\\*", undef,
    sub {
        my $json_raw = shift;
        my $json = get_json($json_raw) or return 0;
        return 0 unless is_int($json->{'volumeSize'}) && $json->{'volumeSize'} == $volumesize && is_int($json->{'replicaCount'}) &&
             $json->{'replicaCount'} == 1 && is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 3;
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/\a'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/\a/'});
        return 0 unless is_hash($json->{'fileList'}->{'/tree/[]/?*\\'});
    };

# List  'tree/[ab]/[ab]''
test_get 'listing all \'tree/[ab]/[ab]\' files', authed_only(200, 'application/json'), "$vol?filter=tree/[ab]/[ab]", undef,
    sub {
        my $json_raw = shift;
        my $json = get_json($json_raw) or return 0;
        return 0 unless is_int($json->{'volumeSize'}) && $json->{'volumeSize'} == $volumesize && is_int($json->{'replicaCount'}) &&
            $json->{'replicaCount'} == 1 && is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 4;
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
        return 0 unless is_int($json->{'volumeSize'}) && $json->{'volumeSize'} == $volumesize && is_int($json->{'replicaCount'}) &&
            $json->{'replicaCount'} == 1 && is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 9;
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



### Check volume modification request ###
test_delete_job "Wiping tiny$vol contents", {'badauth'=>[401],$reader=>[403],$writer=>[200]}, "tiny$vol/toobig";
test_upload 'file upload (add first revision)', $writer, random_data($tinyvolumesize/2-length('toobig')), "tiny$vol", 'toobig';
test_upload 'file upload (overwrite existing revision)', $writer, random_data($tinyvolumesize/2-length('toobig')), "tiny$vol", 'toobig';
test_get 'file revisions (should be 1)', authed_only(200, 'application/json'), "tiny$vol/toobig?fileRevisions", undef, sub { my $json = get_json(shift); return 0 unless is_hash($json->{'fileRevisions'}) && scalar keys %{$json->{'fileRevisions'}} == 1; };
test_put_job "Increasing max revisions for tiny$vol", admin_only(200), "tiny$vol?o=mod", "{\"maxRevisions\":2}";
test_get "tiny$vol max revisions limit modification", {'badauth'=>[401],$reader=>[200,'application/json'],$writer=>[200,'application/json'],'admin'=>[200,'application/json']}, "?volumeList", undef, sub { my $json = get_json(shift); return 0 unless is_hash($json->{'volumeList'}) && is_hash($json->{'volumeList'}->{"tiny$vol"}) && is_int($json->{'volumeList'}->{"tiny$vol"}->{'maxRevisions'}) && $json->{'volumeList'}->{"tiny$vol"}->{'maxRevisions'} == 2; };
test_put_job "Increasing max revisions for tiny$vol (too high)", admin_only(400), "tiny$vol?o=mod", "{\"maxRevisions\":100}"; # Revisions limit is too high
test_put_job "Increasing max revisions for $vol", admin_only(400), "$vol?o=mod", "{\"maxRevisions\":5"; # Will exceed cluster capacity
test_upload 'file upload (add new revision)', $writer, random_data($tinyvolumesize/2-length('toobig')), "tiny$vol", 'toobig';
test_get 'file revisions (should be 2)', authed_only(200, 'application/json'), "tiny$vol/toobig?fileRevisions", undef, sub { my $json = get_json(shift); return 0 unless is_hash($json->{'fileRevisions'}) && scalar keys %{$json->{'fileRevisions'}} == 2; };
test_put_job "Decreasing max revisions for tiny$vol", admin_only(200), "tiny$vol?o=mod", "{\"maxRevisions\":1}"; # New revisions limit is lower than current one
test_upload 'file upload (overwrite existing revision)', $writer, random_data($tinyvolumesize/2-length('toobig')), "tiny$vol", 'toobig'; # This will allow server to finish delete jobs
test_get 'file revisions (should be 1)', authed_only(200, 'application/json'), "tiny$vol/toobig?fileRevisions", undef, sub { my $json = get_json(shift); return 0 unless is_hash($json->{'fileRevisions'}) && scalar keys %{$json->{'fileRevisions'}} == 1; };
$tinyvolumesize = $tinyvolumesize + 2;
test_put_job "Increasing tiny$vol volume size", admin_only(200), "tiny$vol?o=mod", "{\"size\":$tinyvolumesize}"; # Without this change call below should return 413
test_upload 'bigger file upload (overwrite existing revision)', $writer, random_data($tinyvolumesize/2-length('toobig')+1), "tiny$vol", 'toobig';
test_put_job "tiny$vol ownership change (invalid owner)", admin_only(404), "tiny$vol?o=mod", "{\"owner\":\"somebadusername\"}";
test_put_job "tiny$vol ownership change ($reader)", admin_only(200), "tiny$vol?o=mod", "{\"owner\":\"$reader\"}";
test_get 'volume ownership', {$reader=>[200,'application/json']}, "tiny$vol?o=acl", undef, sub { my $json = get_json(shift); my %is_priv = map { $_, 1 } @{$json->{$reader}}; return is_array($json->{$reader}) && $is_priv{'owner'}; };
test_put_job "tiny$vol ownership change (admin)", admin_only(200), "tiny$vol?o=mod", "{\"owner\":\"admin\"}";
test_get 'volume ownership', {'admin'=>[200,'application/json']}, "tiny$vol?o=acl", undef, sub { my $json = get_json(shift); my %is_priv = map { $_, 1 } @{$json->{'admin'}}; return is_array($json->{'admin'}) && $is_priv{'owner'}; };




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
my $wk = random_data(20);
my $rk = random_data(20);
my $rcid = ""; # ID of reader user clone that needs to be saved inside authorisation token 
my $wcid = ""; # ID of writer user clone that needs to be saved inside authorisation token 
my $content;

test_create_user $ru;
test_create_user $wu;

$content = { 'userType' => 'normal', 'userName' => $rc, => 'userKey' => bin_to_hex($rk), 'existingName' => $ru };
test_put_job "$ru cloning ...", admin_only(200), '.users', encode_json($content);
$content = { 'userType' => 'normal', 'userName' => $wc, => 'userKey' => bin_to_hex($wk), 'existingName' => $wu };
test_put_job "$wu cloning ...", admin_only(200), '.users', encode_json($content);

test_get "checking $rc ID", admin_only(200, 'application/json'), ".users/$rc", undef, sub { my $json = get_json(shift) or return 0; return 0 unless is_string($json->{'userID'}); $rcid = $json->{'userID'}; };
test_get "checking $wc ID", admin_only(200, 'application/json'), ".users/$wc", undef, sub { my $json = get_json(shift) or return 0; return 0 unless is_string($json->{'userID'}); $wcid = $json->{'userID'}; };
fail 'Invalid user ID' unless $rcid ne "" && $wcid ne "";

$TOK{$wc} = encode_base64(hex_to_bin($wcid) . $wk . chr(0) . chr(0));
$TOK{$rc} = encode_base64(hex_to_bin($rcid) . $rk . chr(0) . chr(0));

test_put_job "volume creation (clones' volume)", admin_only(200), "clones$vol", "{\"volumeSize\":$tinyvolumesize,\"owner\":\"$wu\"}";
test_put_job 'granting rights on newly created volume', {$wc=>[200],'badauth'=>[401],$rc=>[403],$wu=>[200],$ru=>[403],'admin'=>[200]}, "clones$vol?o=acl", "{\"grant-read\":[\"$ru\",\"$wu\"],\"grant-write\":[\"$wu\"] }";
test_get 'the newly created volume ownership', {'badauth'=>[401],$wu=>[200,'application/json'],'admin'=>[200,'application/json'],$wc=>[200,'application/json']}, "clones$vol?o=acl", undef, sub { my $json = get_json(shift) or return 0; return is_array($json->{$wu}) && @{$json->{$wu}} == 3 && is_array($json->{$ru}) && @{$json->{$ru}} == 1 && is_array($json->{$wc}) && @{$json->{$wc}} == 3 };

test_upload 'file upload (empty file)', $wc, '', "clones$vol", 'empty.clone';
test_get 'listing as cloned users too', {'badauth'=>[401],$ru=>[200,'application/json'],$wu=>[200,'application/json'],'admin'=>[200,'application/json'],$rc=>[200,'application/json'],$wc=>[200,'application/json']},
    "clones$vol?filter=empty.clone", undef, sub { my $json = get_json(shift) or return 0; return is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 1 && is_hash($json->{'fileList'}->{'/empty.clone'}) };

test_delete_job "$wu.clone deletion", admin_only(200), ".users/$wc";
test_upload 'file upload (empty file) again', $wu, '', "clones$vol", 'empty.clone';
test_get 'listing as cloned users too', {'badauth'=>[401],$ru=>[200,'application/json'],$wu=>[200,'application/json'],'admin'=>[200,'application/json'],$rc=>[200,'application/json'],$wc=>[401]},
    "clones$vol?filter=empty.clone", undef, sub { my $json = get_json(shift) or return 0; return is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 1 && is_hash($json->{'fileList'}->{'/empty.clone'}) };

test_get 'if volume is still owned by $wu', {$wu=>[200, 'application/json'],'admin'=>[200, 'application/json']}, "clones$vol?o=acl", undef, sub { my $json = get_json(shift) or return 0; return is_array($json->{$wu}) && @{$json->{$wu}} == 3; };
test_delete_job "$wu deletion", {'admin'=>[200, 'application/json']}, ".users/$wu";
test_get 'if volume is no longer owned by $wu', {'admin'=>[200, 'application/json']}, "clones$vol?o=acl", undef, sub { my $json = get_json(shift) or return 0; return !is_array($json->{$wu}) && is_array($json->{'admin'}) && @{$json->{'admin'}} == 3; };
test_get 'listing as cloned users too', {'badauth'=>[401],$ru=>[200,'application/json'],$wu=>[401],'admin'=>[200,'application/json'],$rc=>[200,'application/json'],$wc=>[401]},
        "clones$vol?filter=empty.clone", undef, sub { my $json = get_json(shift) or return 0; return is_hash($json->{'fileList'}) && scalar keys %{$json->{'fileList'}} == 1 && is_hash($json->{'fileList'}->{'/empty.clone'}) };

# Check listing users by ID
test_get "listing clones of $ru", admin_only(200, 'application/json'), ".users?clones=$ru", undef, sub { my $json = get_json(shift) or return 0; return scalar keys %{$json} == 2 && is_hash($json->{$ru}) && is_hash($json->{$rc}) };

test_delete_job "$rc deletion with all its clones", admin_only(200), ".users/$rc?all";
test_get "checking if $ru was also deleted", admin_only(404), ".users/$ru";

# Check listing users by ID ($ru was removed, this should not return any user)
test_get "listing clones of $ru", admin_only(404), ".users?clones=$ru";

# Check if .status query returns node status
test_get "node status", admin_only(200, 'application/json'), ".status", undef, sub { my $json = get_json(shift); return 0 unless is_string($json->{'osType'}) && is_string($json->{'osArch'}) && is_string($json->{'osRelease'})
    && is_string($json->{'osVersion'}) && is_string($json->{'osEndianness'}) && is_string($json->{'libsxVersion'}) && is_string($json->{'hashFSVersion'}) && is_string($json->{'localTime'}) && is_string($json->{'utcTime'})
    && is_string($json->{'address'}) && is_string($json->{'internalAddress'}) && is_string($json->{'UUID'}) && is_string($json->{'nodeDir'}) && is_int($json->{'storageAllocated'}) && is_int($json->{'storageUsed'}) && is_int($json->{'fsBlockSize'})
    && is_int($json->{'fsTotalBlocks'}) && is_int($json->{'fsAvailBlocks'}) && is_int($json->{'memTotal'}); };


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
test_upload 'file upload to read-only cluster', $writer, '', "large$vol", 'empty';

print "\nTests performed: ".($okies+$fails)." - $fails failed, $okies succeeded\n";
exit ($fails > 0);
