// Generic helper functions
def apt = { packages ->
    ["apt-get update -qq", "apt-get install -y " + packages.join(' '), "apt-get clean"] }

def yum = { packages ->
    ["yum install -y " + packages.join(' '), "yum clean all"] }

def buildIn(base, commands, flags) {
    node('docker') {
        stage 'Checkout'
        // Checkout the branch/commit that triggered the build
        checkout scm
        //        checkout([$class: 'GitSCM', branches:[[name: '**']], extensions: [[$class: 'CleanCheckout']]])

        sh 'rm -rf docker.tmp && mkdir docker.tmp && git archive --format=tgz -1 HEAD >docker.tmp/src.tgz'

        writeFile file:'docker.tmp/Dockerfile', text:([
            "FROM ${base}",
            "RUN useradd jenkins",
            "EXPOSE 80 443 9080 9443",
            "RUN ${commands.join(' && ')}",
            "WORKDIR /usr/src",//cached
            "ADD src.tgz /usr/src/",//not cached from here if src.tar changes
            "RUN chown -R jenkins:jenkins /usr/src",
            "USER jenkins",
            "RUN "+[
                "./configure ${flags}",
                "make",
                "make -j8",
                //  "make check VERBOSE=1"
            ].join(' && '),
            "USER root",
            "RUN make install && rm -rf /usr/src"
            ].join("\n"))

        stage 'Build docker image'
        img=docker.build("build-sx-${base}", 'docker.tmp')

        // TODO: more tests

        // TODO: if we have more slaves then push to local docker registry
    }
}

// SX specific
def deb_packages = [
    'libssl-dev', 'libyajl-dev', 'libfcgi-dev', 'libcurl4-openssl-dev', 'libltdl-dev', 'zlib1g-dev', 'pkg-config',
    'libsqlite3-dev', 'libwww-perl', 'libjson-xs-perl', 'libdigest-hmac-perl', 'liburi-perl', 'libfuse-dev',
    'nginx'
]

def rpm_packages = [
    'libtool-ltdl-devel', 'libtool', 'yajl-devel', 'pkgconfig\\(libcrypto\\)', 'pkgconfig\\(openssl\\)', 'zlib-devel',
    'perl\\(List::Util\\)', 'perl\\(Time::HiRes\\)', 'perl\\(LWP::UserAgent\\)', 'perl\\(URI\\)', 'perl\\(URI::Escape\\)',
    'perl\\(HTTP::Date\\)', 'perl\\(MIME::Base64\\)', 'perl\\(Digest::HMAC_SHA1\\)', 'perl\\(Digest::SHA\\)', 'perl\\(JSON\\)',
    'pkgconfig\\(nss\\)', 'pkgconfig\\(sqlite3\\)', 'curl-devel', 'fuse-devel', 'fcgi-devel', 'nginx'
]

parallel([
// FIXME: --disable-sxhttpd breaks here
'debian': { buildIn('gcc:latest', apt(deb_packages), '--with-system-libs') },
'centos': { buildIn('centos:latest', yum(rpm_packages), '--with-nss --without-openssl') }
])

