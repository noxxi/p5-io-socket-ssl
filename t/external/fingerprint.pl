[
    {
        # this should give us OCSP stapling
        host => 'www.live.com',
        port => 443,
        fingerprint => 'sha1$0e37dc9b320d2526e93e360a26c824b202d1f3af',
	ocsp => { staple => 1 },
    },
    {
        # no OCSP stapling yet
        host => 'www.google.com',
        port => 443,
        fingerprint => 'sha1$89380c438a076d9d5fac228a8f680ff452487f30',
	ocsp => { staple => 0 },
	subject_hash_ca => '578d5c04',
    },
    {
        # this is revoked
        host => 'revoked.grc.com',
        port => 443,
        fingerprint => 'sha1$310665f4c8e78db761c764e798dca66047341264',
	ocsp => { revoked => 1 },
    },
    {
        host => 'www.yahoo.com',
        port => 443,
        fingerprint => 'sha1$413072f803ce961210e9a45d10da14b0d2d48532',
	subject_hash_ca => '415660c1',
    },
    {
        host => 'www.comdirect.de',
        port => 443,
        fingerprint => 'sha1$98e2aceff740fb0557ab221d464237b141fdb5aa',
	subject_hash_ca => '415660c1',
    },
    {
        host => 'meine.deutsche-bank.de',
        port => 443,
        fingerprint => 'sha1$5df0a055a5db14830285f356c60fa262c0e04778',
	subject_hash_ca => '415660c1',
    },
    {
        host => 'www.twitter.com',
        port => 443,
        fingerprint => 'sha1$14a16b4213412064debbe08adcf36f417e5077d5',
	subject_hash_ca => '244b5494',
    },
    {
        host => 'www.facebook.com',
        port => 443,
        fingerprint => 'sha1$a04eafb348c26b15a8c1aa87a333caa3cdeec9c9',
	subject_hash_ca => '244b5494',
    },
    {
        host => 'www.live.com',
        port => 443,
        fingerprint => 'sha1$0e37dc9b320d2526e93e360a26c824b202d1f3af',
	subject_hash_ca => 'b204d74a',
    },

];
