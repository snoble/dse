package dse{
	import com.hurlant.crypto.prng.Random;
	import com.hurlant.crypto.rsa.RSAKey;
	import com.hurlant.util.Hex;
	import com.hurlant.crypto.prng.TLSPRF;
	
	import flash.external.ExternalInterface;
	import flash.utils.ByteArray;
	public class KeyGenerator
	{
		public static function generateKeys():void{
			var exp:String = "10001";
			var rsa:RSAKey = RSAKey.generate(1024, exp);
			ExternalInterface.call("setvalue", "publickey", rsa.n.toString());
			ExternalInterface.call("setvalue", "d", rsa.d.toString());
			ExternalInterface.call("setvalue", "p", rsa.p.toString());
			ExternalInterface.call("setvalue", "q", rsa.q.toString());
			ExternalInterface.call("setvalue", "dmp", rsa.dmp1.toString());
			ExternalInterface.call("setvalue", "dmq", rsa.dmq1.toString());
			ExternalInterface.call("setvalue", "qinv", rsa.coeff.toString());
			var data:ByteArray, prehashedkey:ByteArray, hashedkey:ByteArray;
				
			var r:Random = new Random(TLSPRF);
			var rankey:ByteArray = new ByteArray;
			r.nextBytes(rankey, 32);
			ExternalInterface.call("setvalue", "rk", Hex.fromArray(rankey));
		}
	}
}

