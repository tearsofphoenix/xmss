var xmss = require('../');
var crypto = require('crypto');
var assert = require('assert');

describe('xmss test', function () {
    var pair = xmss.createKeypair();
    it('should create key pair', function () {
        this.timeout(20 * 1000);
        console.log(pair);
    });

    it('should sign data', function () {
        this.timeout(20 * 1000);
        var msg = new Uint8Array([11, 12, 13, 14, 15, 16, 17, 18, 11, 12, 13, 14, 15, 16, 17, 18,
            11, 12, 13, 14, 15, 16, 17, 18, 11, 12, 13, 14, 15, 16, 17, 18, 11, 12, 13, 14, 15, 16, 17, 18,
            11, 12, 13, 14, 15, 16, 17, 18, 11, 12, 13, 14, 15, 16, 17, 18, 11, 12, 13, 14, 15, 16, 17, 18]);
        var sig = xmss.sign(msg, pair.private);
        console.log(sig);
    });

    it('should verify data', function () {
        pair = xmss.createKeypair();
        this.timeout(20 * 1000);
        var msg = new Uint8Array([11, 12, 13, 14, 15, 16, 17, 18, 11, 12, 13, 14, 15, 16, 17, 18,
            11, 12, 13, 14, 15, 16, 17, 18, 11, 12, 13, 14, 15, 16, 17, 18, 11, 12, 13, 14, 15, 16, 17, 18,
            11, 12, 13, 14, 15, 16, 17, 18, 11, 12, 13, 14, 15, 16, 17, 18, 11, 12, 13, 14, 15, 16, 17, 18]);
        var sig = xmss.sign(msg, pair.private);
        var ret = xmss.verify(sig, msg, pair.public);
        assert.equal(ret, true);
    });

    it('should create from seed', function () {
        this.timeout(20 * 1000);
        var seed = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        var p2 = xmss.createKeypair(seed);
        var p3 = xmss.createKeypair(seed);
        assert.deepEqual(p2.private, p3.private);
        assert.deepEqual(p2.public, p3.public);
    });

    it('should not verify data', function () {
        pair = xmss.createKeypair();
        this.timeout(20 * 1000);
        var msg = new Uint8Array([11, 12, 13, 14, 15, 16, 17, 18, 11, 12, 13, 14, 15, 16, 17, 18,
            11, 12, 13, 14, 15, 16, 17, 18, 11, 12, 13, 14, 15, 16, 17, 18, 11, 12, 13, 14, 15, 16, 17, 18,
            11, 12, 13, 14, 15, 16, 17, 18, 11, 12, 13, 14, 15, 16, 17, 18, 11, 12, 13, 14, 15, 16, 17, 18]);
        var sig = xmss.sign(msg, pair.private);
        var invalidPublicKey = crypto.randomBytes(pair.public.length);
        var ret = xmss.verify(sig, msg, invalidPublicKey);
        assert.equal(ret, false);
    });
});
