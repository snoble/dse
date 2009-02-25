package dse{
	import com.hurlant.crypto.Crypto;
	import com.hurlant.crypto.hash.IHash;
	import com.hurlant.crypto.prng.Random;
	import com.hurlant.crypto.rsa.RSAKey;
	import com.hurlant.util.Hex;
	
	import flash.external.ExternalInterface;
	import flash.utils.ByteArray;
	
	public class KeyGenerator
	{
		public static function generateKeys(passphrase:String):void{
			var exp:String = "10001";
			var rsa:RSAKey = RSAKey.generate(1024, exp);
			ExternalInterface.call("setvalue", "publickey", rsa.n.toString());
			ExternalInterface.call("setvalue", "d", rsa.d.toString());
			ExternalInterface.call("setvalue", "p", rsa.p.toString());
			ExternalInterface.call("setvalue", "q", rsa.q.toString());
			ExternalInterface.call("setvalue", "dmp", rsa.dmp1.toString());
			ExternalInterface.call("setvalue", "dmq", rsa.dmq1.toString());
			ExternalInterface.call("setvalue", "qinv", rsa.coeff.toString());
				
			var r:Random = new Random;
			var rankey:ByteArray = new ByteArray; var discard:ByteArray = new ByteArray;

			//incorporate passphrase into seeding process
			var hash:IHash = Crypto.getHash("sha256");
			var p:ByteArray = hash.hash(Hex.toArray(Hex.fromString(passphrase)));
			r.autoSeed();
			while (p.bytesAvailable>=4) {
				r.seed(p.readUnsignedInt());
			}

			r.nextBytes(discard, 1024);
			r.nextBytes(rankey, 32);
			ExternalInterface.call("setvalue", "rk", Hex.fromArray(rankey));
		}
	}
}

