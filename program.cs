using System;
using System.Linq;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
	
public class Program
{
	public static void Main()
	{
	  byte[] prvKey = new byte[32];
	  ECPoint pubKey;
      byte[] address = new byte[20];
		
	  // generate prvKey and pubKey
	  ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
	  ECParameters ecParameters = ecdsa.ExportParameters(true);
	  prvKey = ecParameters.D;
	  pubKey = ecParameters.Q;
	  
	  // generate address
	  byte[] concatenatedPubKey = pubKey.X.Concat(pubKey.Y).ToArray();
	  IDigest hash = new KeccakDigest(256);
	  hash.BlockUpdate(concatenatedPubKey, 0, concatenatedPubKey.Length);
	  byte[] PubKeyHash = new byte[32];
	  hash.DoFinal(PubKeyHash, 0);
	  address = PubKeyHash.Skip(PubKeyHash.Length - 20).Take(20).ToArray();
		
	  // display 
	  string privateKeyString = FormatByteArray(prvKey);
	  Console.WriteLine("private key: " + privateKeyString);
	  string x = FormatByteArray(pubKey.X);
	  string y = FormatByteArray(pubKey.Y);
	  Console.WriteLine("public key: ({0}, {1})", x, y);
	  string addressString = FormatByteArray(address);
	  Console.WriteLine("address: " + "0x" + addressString);
	}
	
	private static string FormatByteArray(byte[] input){
	  return BitConverter.ToString(input).Replace("-", "").ToLower(); 
	}
}