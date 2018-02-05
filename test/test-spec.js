var xmss = require('../');

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
        this.timeout(20 * 1000);
        var msg = new Uint8Array([11, 12, 13, 14, 15, 16, 17, 18, 11, 12, 13, 14, 15, 16, 17, 18,
            11, 12, 13, 14, 15, 16, 17, 18, 11, 12, 13, 14, 15, 16, 17, 18, 11, 12, 13, 14, 15, 16, 17, 18,
            11, 12, 13, 14, 15, 16, 17, 18, 11, 12, 13, 14, 15, 16, 17, 18, 11, 12, 13, 14, 15, 16, 17, 18]);
        var sig = xmss.sign(msg, pair.private);
        var ret = xmss.verify(sig, msg, pair.public);
        console.log(sig, ret);
    });
});
