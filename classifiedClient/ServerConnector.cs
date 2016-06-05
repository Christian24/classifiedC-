using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Tls;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using System.Net.Http;
using System.Net;
using Newtonsoft.Json;

namespace classifiedClient
{
	public class ServerConnector
	{
		protected string masterkey;
		protected string private_key_encoded;
		protected string salt_masterkey;
		protected string public_key;
		protected string private_key;
		public async Task<HttpStatusCode> Register(String userName, String password)
		{
			byte[] bytes = new byte[64];
			using (var random = new RNGCryptoServiceProvider())
			{
				random.GetNonZeroBytes(bytes);
			}
			
			var salt = System.Text.Encoding.Default.GetString(bytes);
			
		var masterkey=	PBKDF2Sha256GetBytes(32, Encoding.Default.GetBytes(password), bytes, 10000);
			Console.WriteLine("Masterkey: " + Encoding.Default.GetString(masterkey));
			// Create a new instance of RSACryptoServiceProvider to generate
			//public and private key data.  Pass an integer specifying a key-
			//length of 2048.
			//	RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider(2048);
			//	using (TextWriter writer =new StreamWriter( File.Open("public.key",FileMode.CreateNew)))
			//	{
			//		ExportPublicKey(RSAalg, writer);

			//	}
			//	string publicKey = "";
			//	using (StreamReader reader = new StreamReader(File.Open("public.key", FileMode.Open)))
			//	{
			//publicKey=		reader.ReadToEnd();
			//	}
			//	AesManaged aes = new AesManaged();
			//	//aes.KeySize = 128;
			//	aes.BlockSize = 128;
			//	aes.Mode = CipherMode.ECB;
			//aes.CreateEncryptor(masterkey,)
			RsaKeyPairGenerator rsa = new RsaKeyPairGenerator();
			rsa.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new Org.BouncyCastle.Security.SecureRandom(), 2048));
			var keys = rsa.GenerateKeyPair();
			

			string privateKey = getStringFromKey(keys.Private);
			string publicKey = getStringFromKey(keys.Public);
			


			var aes =AesManaged.Create();
			aes.BlockSize = 128;
			aes.Mode = CipherMode.ECB;
			aes.Key = masterkey;
		var encryptor=	aes.CreateEncryptor();
			var privateBytes = Encoding.Default.GetBytes(privateKey);
		var private_key_enc=	encryptor.TransformFinalBlock(privateBytes, 0, privateBytes.Length);
			var private_key_export = Encoding.Default.GetString(private_key_enc);
			using (var client = new HttpClient())
			{
				Dictionary<string, string> param = new Dictionary<string, string>();
				param.Add("login", userName);
				param.Add("salt_masterkey", salt);
				param.Add("pubkey_user", publicKey);
				param.Add("privkey_user_enc", Base64Encode(private_key_export));
				var content = new FormUrlEncodedContent(param);
			var result = await client.PostAsync("https://webengserver.herokuapp.com/" + userName, content);

				return result.StatusCode;
			}	
			
		}
		public async Task<HttpStatusCode> Login(string userName, string password)
		{
			using (var client = new HttpClient())
			{
				var result = await client.GetAsync("https://webengserver.herokuapp.com/" + userName);
				if(result.StatusCode == HttpStatusCode.OK)
				{
				var content = await	result.Content.ReadAsStringAsync();
				dynamic response =	JsonConvert.DeserializeObject(content);
		salt_masterkey=			response.salt_masterkey;
					public_key = response.pubkey_user;
					private_key_encoded = response.privkey_user_enc;
var masterkeyBytes = 	PBKDF2Sha256GetBytes(32, Encoding.Default.GetBytes(password),Encoding.Default.GetBytes( salt_masterkey), 10000);

						masterkey = Encoding.Default.GetString(masterkeyBytes);
					System.Console.WriteLine("Masterkey: " + masterkey);
					var aes = AesManaged.Create();
					aes.BlockSize = 128;
					aes.Mode = CipherMode.ECB;
					aes.Key = masterkeyBytes;
					var decryptor = aes.CreateDecryptor();
					var bytes = Encoding.Default.GetBytes(private_key_encoded);
					try
					{
						private_key = Encoding.Default.GetString(decryptor.TransformFinalBlock(bytes, 0, bytes.Length));
						return result.StatusCode;
					}
					catch (Exception)
					{

						throw;
					}
			//private_key=	Encoding.Default.GetString(	decryptor.TransformFinalBlock(bytes, 0, bytes.Length));

					return result.StatusCode;
				}
				return result.StatusCode;
			}
		}
		private string getStringFromKey(AsymmetricKeyParameter key)
		{
			string export = "";
			using (TextWriter writer = new StringWriter())
			{
				PemWriter pemWriter = new PemWriter(writer);
				pemWriter.WriteObject(key);
				writer.Flush();
				export = writer.ToString();
			}
			return export;
		}
		/// <summary>
		/// Taken from http://stackoverflow.com/questions/11743160/how-do-i-encode-and-decode-a-base64-string
		/// </summary>
		/// <param name="plainText"></param>
		/// <returns></returns>
		public static string Base64Encode(string plainText)
		{
			var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
			return System.Convert.ToBase64String(plainTextBytes);
		}
		/// <summary>
		/// Taken from http://stackoverflow.com/questions/11743160/how-do-i-encode-and-decode-a-base64-string
		/// </summary>
		/// <param name="base64EncodedData"></param>
		/// <returns></returns>
		public static string Base64Decode(string base64EncodedData)
		{
			var base64EncodedBytes = System.Convert.FromBase64String(base64EncodedData);
			return System.Text.Encoding.UTF8.GetString(base64EncodedBytes);
		}

		/// <summary>
		/// Taken from http://stackoverflow.com/questions/28406888/c-sharp-rsa-public-key-output-not-correct/28407693#28407693
		/// </summary>
		/// <param name="csp"></param>
		/// <param name="outputStream"></param>
		private static void ExportPublicKey(RSACryptoServiceProvider csp, TextWriter outputStream)
		{
			var parameters = csp.ExportParameters(false);
			using (var stream = new MemoryStream())
			{
				var writer = new BinaryWriter(stream);
				writer.Write((byte)0x30); // SEQUENCE
				using (var innerStream = new MemoryStream())
				{
					var innerWriter = new BinaryWriter(innerStream);
					innerWriter.Write((byte)0x30); // SEQUENCE
					EncodeLength(innerWriter, 13);
					innerWriter.Write((byte)0x06); // OBJECT IDENTIFIER
					var rsaEncryptionOid = new byte[] { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
					EncodeLength(innerWriter, rsaEncryptionOid.Length);
					innerWriter.Write(rsaEncryptionOid);
					innerWriter.Write((byte)0x05); // NULL
					EncodeLength(innerWriter, 0);
					innerWriter.Write((byte)0x03); // BIT STRING
					using (var bitStringStream = new MemoryStream())
					{
						var bitStringWriter = new BinaryWriter(bitStringStream);
						bitStringWriter.Write((byte)0x00); // # of unused bits
						bitStringWriter.Write((byte)0x30); // SEQUENCE
						using (var paramsStream = new MemoryStream())
						{
							var paramsWriter = new BinaryWriter(paramsStream);
							EncodeIntegerBigEndian(paramsWriter, parameters.Modulus); // Modulus
							EncodeIntegerBigEndian(paramsWriter, parameters.Exponent); // Exponent
							var paramsLength = (int)paramsStream.Length;
							EncodeLength(bitStringWriter, paramsLength);
							bitStringWriter.Write(paramsStream.GetBuffer(), 0, paramsLength);
						}
						var bitStringLength = (int)bitStringStream.Length;
						EncodeLength(innerWriter, bitStringLength);
						innerWriter.Write(bitStringStream.GetBuffer(), 0, bitStringLength);
					}
					var length = (int)innerStream.Length;
					EncodeLength(writer, length);
					writer.Write(innerStream.GetBuffer(), 0, length);
				}

				var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length).ToCharArray();
				outputStream.WriteLine("-----BEGIN PUBLIC KEY-----");
				for (var i = 0; i < base64.Length; i += 64)
				{
					outputStream.WriteLine(base64, i, Math.Min(64, base64.Length - i));
				}
				outputStream.WriteLine("-----END PUBLIC KEY-----");
			}
		}
		/// <summary>
		/// Taken from http://stackoverflow.com/questions/23734792/c-sharp-export-private-public-rsa-key-from-rsacryptoserviceprovider-to-pem-strin
		/// </summary>
		/// <param name="stream"></param>
		/// <param name="value"></param>
		/// <param name="forceUnsigned"></param>
		private static void EncodeIntegerBigEndian(BinaryWriter stream, byte[] value, bool forceUnsigned = true)
		{
			stream.Write((byte)0x02); // INTEGER
			var prefixZeros = 0;
			for (var i = 0; i < value.Length; i++)
			{
				if (value[i] != 0) break;
				prefixZeros++;
			}
			if (value.Length - prefixZeros == 0)
			{
				EncodeLength(stream, 1);
				stream.Write((byte)0);
			}
			else
			{
				if (forceUnsigned && value[prefixZeros] > 0x7f)
				{
					// Add a prefix zero to force unsigned if the MSB is 1
					EncodeLength(stream, value.Length - prefixZeros + 1);
					stream.Write((byte)0);
				}
				else
				{
					EncodeLength(stream, value.Length - prefixZeros);
				}
				for (var i = prefixZeros; i < value.Length; i++)
				{
					stream.Write(value[i]);
				}
			}
		}
		/// <summary>
		/// Taken from http://stackoverflow.com/questions/23734792/c-sharp-export-private-public-rsa-key-from-rsacryptoserviceprovider-to-pem-strin
		/// </summary>
		/// <param name="stream"></param>
		/// <param name="length"></param>
		private static void EncodeLength(BinaryWriter stream, int length)
		{
			if (length < 0) throw new ArgumentOutOfRangeException("length", "Length must be non-negative");
			if (length < 0x80)
			{
				// Short form
				stream.Write((byte)length);
			}
			else
			{
				// Long form
				var temp = length;
				var bytesRequired = 0;
				while (temp > 0)
				{
					temp >>= 8;
					bytesRequired++;
				}
				stream.Write((byte)(bytesRequired | 0x80));
				for (var i = bytesRequired - 1; i >= 0; i--)
				{
					stream.Write((byte)(length >> (8 * i) & 0xff));
				}
			}
		}

		/// <summary>
		/// Taken from http://stackoverflow.com/questions/18648084/rfc2898-pbkdf2-with-sha256-as-digest-in-c-sharp
		///  NOTE: The iteration count should be as high as possible without causing
		/// unreasonable delay.  Note also that the password
		/// and salt are byte arrays, not strings.  After use,
		/// the password and salt should be cleared (with Array.Clear)
		/// </summary>
		/// <param name="dklen"></param>
		/// <param name="password"></param>
		/// <param name="salt"></param>
		/// <param name="iterationCount"></param>
		/// <returns></returns>
		public static byte[] PBKDF2Sha256GetBytes(int dklen, byte[] password, byte[] salt, int iterationCount)
		{
			using (var hmac = new System.Security.Cryptography.HMACSHA256(password))
			{
				int hashLength = hmac.HashSize / 8;
				if ((hmac.HashSize & 7) != 0)
					hashLength++;
				int keyLength = dklen / hashLength;
				if ((long)dklen > (0xFFFFFFFFL * hashLength) || dklen < 0)
					throw new ArgumentOutOfRangeException("dklen");
				if (dklen % hashLength != 0)
					keyLength++;
				byte[] extendedkey = new byte[salt.Length + 4];
				Buffer.BlockCopy(salt, 0, extendedkey, 0, salt.Length);
				using (var ms = new System.IO.MemoryStream())
				{
					for (int i = 0; i < keyLength; i++)
					{
						extendedkey[salt.Length] = (byte)(((i + 1) >> 24) & 0xFF);
						extendedkey[salt.Length + 1] = (byte)(((i + 1) >> 16) & 0xFF);
						extendedkey[salt.Length + 2] = (byte)(((i + 1) >> 8) & 0xFF);
						extendedkey[salt.Length + 3] = (byte)(((i + 1)) & 0xFF);
						byte[] u = hmac.ComputeHash(extendedkey);
						Array.Clear(extendedkey, salt.Length, 4);
						byte[] f = u;
						for (int j = 1; j < iterationCount; j++)
						{
							u = hmac.ComputeHash(u);
							for (int k = 0; k < f.Length; k++)
							{
								f[k] ^= u[k];
							}
						}
						ms.Write(f, 0, f.Length);
						Array.Clear(u, 0, u.Length);
						Array.Clear(f, 0, f.Length);
					}
					byte[] dk = new byte[dklen];
					ms.Position = 0;
					ms.Read(dk, 0, dklen);
					ms.Position = 0;
					for (long i = 0; i < ms.Length; i++)
					{
						ms.WriteByte(0);
					}
					Array.Clear(extendedkey, 0, extendedkey.Length);
					return dk;
				}
			}
		}
		}
}
