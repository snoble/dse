
function DSEKey(){
  this.decryptprepared = false;
  this.encryptprepared = false;
  this.rsakey = new RSAKey();
  this.publickey = null; //Hex of RSA publickey
  this.rk = null; //Hex of random AES key
  this.fk = null; //string of json containing 
  this.ed = null; //Hex of private RSA exponent encrypted with passphrase AES key
  this.erk = null; //Hex of random AES key encrypted with RSA key
  this.efk = null; //Hex of fk encrypted with random AES key
  this.d = null; //Hex of private RSA exponent
  this.p = null; //Hex of private RSA prime p
  this.q = null; //Hex of private RSA prime q
  this.dmp = null; //Hex of d mod p
  this.dmq = null; //Hex of d mod q
  this.qinv = null; //Hex of inverse of q in the finite field of order p
  this.passphrase = ""; //Passphrase for generating AES key
}

var prng;

//depends on rk, d, p, q, dmp, dmq, qinv being set by setKeys
function DSEencryptKeys(){
  var aeskey = hexToByteArray(hex_sha256(this.passphrase));
  var mode = "CBC";
  prng = new SecureRandom();
  prng.nextInt = function(n){
    var ret = [0];
    prng.nextBytes(ret);
    return ret[0];
  }
  this.ed = byteArrayToHex(
    rijndaelEncrypt(hexToByteArray(this.d), aeskey, mode)
  );
  this.rsakey.setPublic(this.publickey, "10001");
  this.erk = this.rsakey.encrypt(hexToByteString(this.rk));
  this.fk = '{publickey:"' + this.publickey + 
    '",d:"' + this.d +
    '",p:"' + this.p +
    '",q:"' + this.q +
    '",dmp:"' + this.dmp +
    '",dmq:"' + this.dmq +
    '",qinv:"' + this.qinv + '"}';
  this.efk = byteArrayToHex(
    rijndaelEncrypt(this.fk, hexToByteArray(this.rk), mode)
  );
  return this;
}

//Returns the versions of the keys that can be safely seen by a 3rd party.
//This object can be passed to setKeys to do things like encrypting and decrypting messages
function DSEgetSafeKeys(){
  return {publickey: this.publickey, ed:this.ed, erk:this.erk, efk:this.efk};
}

function DSEsetKeys(keys){
  for(var j in keys){
    this[j] = keys[j];
  }
  return this;
}

//depends on passphrase, publicKey, erk, ed, efk being set by setKeys
function DSEdecryptKeys(){
  var aeskey = hexToByteArray(hex_sha256(this.passphrase));
  var mode = "CBC";
  var ciphertext = hexToByteArray(this.ed);
  var d = rijndaelDecrypt(ciphertext, aeskey, mode);
  this.d = byteArrayToHex(d);
  this.rsakey = new RSAKey();
  this.rsakey.setPrivate(this.publickey, "10001", this.d);
  var randomaeskeybs = this.rsakey.decrypt(this.erk);
  if(randomaeskeybs == null){
    return false;
  }
  var randomaeskeybs = cleanByteString(randomaeskeybs);
  var randomaeskey = byteStringToByteArray(randomaeskeybs);
  ciphertext = hexToByteArray(this.efk);
  var pkjson = rijndaelDecrypt(ciphertext, randomaeskey, mode);
  pkjson = byteArrayToByteString(pkjson);
  var pkex = eval(pkjson);
  for(var i in pkex){
    this[i] = this[i];
  }
  return true;
}

function byteStringToByteArray(text){
  var data = [];
  var cc, left, right;
  for(var j = 0; j<text.length; j++){
    cc = text.charCodeAt(j);
    left = cc >>> 8;
    right = cc - (left << 8);
    data[j] = cc;
  }
  return data;
}

function byteArrayToByteString(data){
  var text = "";
  for(var j in data){
    text = text + String.fromCharCode(data[j] >= 0 ? data[j] : data[j] +256);
  }
  return text;
}

function cleanByteString(bs){
  var newbs = '';
  for(var j = 0; j<bs.length; j++){
    newbs = newbs +  (bs.charCodeAt(j) < 256 ? bs.charAt(j) : String.fromCharCode(bs.charCodeAt(j) -0xFF00));
  }
  return newbs;
}

function hexToByteString(hex){
  var text = "";
  if(hex.length % 2 != 0)
    hex = "0" + hex;
  for(var j = 0; j<hex.length; j++)
    text = text + String.fromCharCode(parseInt(hex.substr(2*j, 2), 16));
  return text;
}


//depends on passphrase, publicKey, erk, ed, efk being set by setKeys
//in theory this will encrypt a message of any length but if you exceed 
//20 block lengths (320 characters with a 1024 bit key) information
//about the message length is exposed in the length of the cipher text
function DSEencryptPlainText(plaintext){
  if(!this.encryptprepared){
    this.rsakey.setPublic(this.publickey, "10001");
    this.encryptprepared = true;
  }
  var ciphertext = "";
  var n = (this.rsakey.n.bitLength() + 7 >> 3) - 11;
  for(var i=0; i < plaintext.length; i += n){
    var block = plaintext.substr(i, n);
    ciphertext += this.rsakey.encrypt(block);
  }
  for(i; i< n*20; i += n){
    ciphertext += this.rsakey.encrypt("");
  }
  return ciphertext;
}

//depends on passphrase, publicKey, erk, ed, efk being set by setKeys
function DSEdecryptCipherText(ciphertext){
  if(!this.decryptprepared){
    this.decryptprepared = this.decryptKeys();
    if(!this.decryptprepared) return;	
  }
  this.rsakey = new RSAKey();
  if(this.p == '' || this.p == null){
    this.rsakey.setPrivate(this.publickey, "10001", this.d);
  }else{
    this.rsakey.setPrivateEx(this.publickey, "10001", this.d, this.p, this.q, this.dmp, this.dmq, this.qinv);
  }
  var n = (this.rsakey.n.bitLength() + 7 >> 3);
  var plaintext = "";
    var plainblock;
    for(var i=0; i< ciphertext.length; i += (2*n)){
      plainblock = this.rsakey.decrypt(ciphertext.substr(i,2*n));
      if(plainblock == "" || plainblock == null) {break;}
        plaintext += plainblock;
    }
  return plaintext
}

DSEKey.prototype.encryptKeys = DSEencryptKeys;
DSEKey.prototype.encryptPlainText = DSEencryptPlainText;
DSEKey.prototype.decryptCipherText = DSEdecryptCipherText;
DSEKey.prototype.decryptKeys = DSEdecryptKeys;
DSEKey.prototype.setKeys = DSEsetKeys;
DSEKey.prototype.getSafeKeys = DSEgetSafeKeys;
DSEKey.prototype.encryptKeys = DSEencryptKeys;

