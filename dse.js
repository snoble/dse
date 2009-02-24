
function DSEKey(){
  this.decryptprepared = false;
  this.encryptprepared = false;
  this.rsakey = new RSAKey();
  this.publickey = null;
  this.rk = null;
  this.fk = null;
  this.ed = null;
  this.erk = null;
  this.efk = null;
  this.d = null;
  this.p = null;
  this.q = null;
  this.dmp = null;
  this.dmq = null;
  this.qinv = null;
  this.passphrase = ""; 
}

var prng;

//depends on rk, d, p, q, dmp, dmq, qinv
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

function DSEgetSafeKeys(){
  return {publickey: this.publickey, ed:this.ed, erk:this.erk, efk:this.efk};
}

function DSEsetKeys(keys){
  for(var j in keys){
    this[j] = keys[j];
  }
  return this;
}

function DSEdecryptKeys(){
  var aeskey = hexToByteArray(hex_sha256(this.passphrase));
  var mode = "CBC";
  var ciphertext = hexToByteArray(this.ed);
  var d = rijndaelDecrypt(ciphertext, aeskey, mode);
  this.d = byteArrayToHex(d);
  while(this.d.substr(this.d.length-2) == '00'){
    this.d = this.d.substr(0, this.d.length -2);
  }
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
  for(i; i< n*10; i += n){
    ciphertext += this.rsakey.encrypt("");
  }
  return ciphertext;
}

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

