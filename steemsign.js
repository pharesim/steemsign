function normalize_brainKey(brainKey) {
  	if (!(typeof brainKey === 'string')) {
		throw new Error("string required for brainKey");
	}

	brainKey = brainKey.trim();
    return brainKey.split(/[\t\n\v\f\r ]+/).join(' ');
}

function fromSeed(seed) {
	return normalize_brainKey(Sha256.hash(seed));
}

function generateKey(accountName, password, role) {
    seed = accountName + role + password;
    return fromSeed(seed);
}

function fromWif(_private_wif) {        
    var private_wif = bs58decode(_private_wif);
    var private_key = private_wif.slice(0, -4);
    private_key = private_key.slice(1);
    var h = '';
    for (var i = 0; i < private_key.length; i++) {
        h += private_key[i].toString(16);
    }
    return h;
}

function bs58decode(string) {
	var ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
	var ALPHABET_MAP = {}
	var BASE = ALPHABET.length
	var LEADER = ALPHABET.charAt(0)

	// pre-compute lookup table
	for (var i = 0; i < ALPHABET.length; i++) {
	    ALPHABET_MAP[ALPHABET.charAt(i)] = i
	}

    if (string.length === 0) return []

    var bytes = [0]
    for (var i = 0; i < string.length; i++) {
      var value = ALPHABET_MAP[string[i]]
      if (value === undefined) throw new Error('Non-base' + BASE + ' character')

      for (var j = 0, carry = value; j < bytes.length; ++j) {
        carry += bytes[j] * BASE
        bytes[j] = carry & 0xff
        carry >>= 8
      }

      while (carry > 0) {
        bytes.push(carry & 0xff)
        carry >>= 8
      }
    }

    // deal with leading zeros
    for (var k = 0; string[k] === LEADER && k < string.length - 1; ++k) {
      bytes.push(0)
    }

    return bytes.reverse()
}

function base_expiration_sec(time_string) {
    var head_block_sec = Math.ceil(timeStringToDate(time_string).getTime() / 1000);
    var now_sec = Math.ceil(Date.now() / 1000);
    // The head block time should be updated every 3 seconds.  If it isn't
    // then help the transaction to expire (use head_block_sec)
    if (now_sec - head_block_sec > 30) { return head_block_sec; }
    // If the user's clock is very far behind, use the head block time.
    return Math.max(now_sec, head_block_sec);
}

function timeStringToDate(time_string) {
    if( ! time_string) return new Date("1970-01-01T00:00:00.000Z")
    if( ! /Z$/.test(time_string)) //does not end in Z
        // https://github.com/cryptonomex/graphene/issues/368
        time_string = time_string + "Z"
    return new Date(time_string)
}

function sign(steem){
	console.log('test');
	chain_id = "0000000000000000000000000000000000000000000000000000000000000000";
	steem.send('get_dynamic_global_properties',[], function(r) {
		var tx = {};
        head_block_time_string = r.time;
        tx.expiration = base_expiration_sec(head_block_time_string) + 15;
        tx.ref_block_num = r.head_block_number & 0xFFFF;
        tx.ref_block_prefix = parseInt(r.head_block_id.substring(14,16)+r.head_block_id.substring(12,14)+r.head_block_id.substring(10,12)+r.head_block_id.substring(8,10),16);
        tx.operations = [['transfer',{'from':'tester1','to':'tester2','amount':'0.000 STEEM','memo':'memo'}]];
        var b = new ByteBuffer(ByteBuffer.DEFAULT_CAPACITY, ByteBuffer.LITTLE_ENDIAN);
        b.append(tx);
        console.log(b);
        tx.tr_buffer = this.toByteBuffer(tx).toBinary();
    });


    buf = Buffer.concat([new Buffer(chain_id, 'hex'), this.tr_buffer])
    var buf_sha256 = hash.sha256(buf);
    var der, e, ecsignature, i, lenR, lenS, nonce;
    i = null;
    nonce = 0;
    e = BigInteger.fromBuffer(buf_sha256);
    while (true) {
      ecsignature = ecdsa.sign(secp256k1, buf_sha256, private_key.d, nonce++);
      der = ecsignature.toDER();
      lenR = der[3];
      lenS = der[5 + lenR];
      if (lenR === 32 && lenS === 32) {
        i = ecdsa.calcPubKeyRecoveryParam(secp256k1, e, ecsignature, private_key.toPublicKey().Q);
        i += 4;  // compressed
        i += 27; // compact  //  24 or 27 :( forcing odd-y 2nd key candidate)
        break;
      }
      if (nonce % 10 === 0) {
        console.log("WARN: " + nonce + " attempts to find canonical signature");
      }
    }
	var sig = new Signature(ecsignature.r, ecsignature.s, i);
    this.signatures.push(sig.toBuffer());
    this.signer_private_keys = [];
    this.signed = true;
    return;
}

var server = 'wss://this.piston.rocks';
var ws = new WebSocketWrapper(server);
ws.connect().then(function(response) {
    var steem = new SteemWrapper(ws);  
    var seed = 'test23';
	var username = 'tester';
	var password = 'test234';
	sign(steem);
	console.log(username+' active key: '+generateKey(username, password, 'active'));
	console.log(fromSeed(seed));
	console.log(fromWif('5JVhPmd2aos8LvvEB9vFaeSPFPVmST6jSkyNrzR5r9nK52F5so8'));
});