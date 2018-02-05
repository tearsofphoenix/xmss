var os = require('os');
var oldpath = process.cwd();
process.chdir(module.filename.replace('main.js',''));
var addon = require('./lib/addon-'+os.platform()+'-'+os.arch());
process.chdir(oldpath);


module.exports = {
    createKeypair: function () {
        return addon.createKeypair();
    },
    sign: function (message, privateKey) {
        var abi = addon.sign(message, privateKey);
	    return abi.buffer.slice(0, abi.length);
    },
    verify: function (signature, message, publicKey) {
        var abi = addon.verify(signature, message, publicKey);
        return abi[0];
    }
};
