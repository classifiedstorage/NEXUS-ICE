using System;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace ICE
{
    public static class Script
    {
        public static string ConstructToken()
        {
            string data = GetIpAddress() + ":" + GetPort();
            byte[] bytesToEncrypt = Encoding.UTF8.GetBytes(data);
            Array.Reverse(bytesToEncrypt);
            return Convert.ToBase64String(bytesToEncrypt);
        }

        public static string[] DeconstructToken(string token)
        {
            byte[] bytesToDecrypt = Convert.FromBase64String(token);
            Array.Reverse(bytesToDecrypt);
            return Encoding.UTF8.GetString(bytesToDecrypt).Split(':');
        }

        private static string GetIpAddress()
        {
            foreach (NetworkInterface item in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (item.OperationalStatus == OperationalStatus.Up)
                {
                    foreach (UnicastIPAddressInformation ip in item.GetIPProperties().UnicastAddresses)
                    {
                        if (ip.Address.AddressFamily == AddressFamily.InterNetwork)
                        {
                            return ip.Address.ToString();
                        }
                    }
                }
            }
            return string.Empty;
        }

        private static int GetPort()
        {
            TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            return port;
        }
    }

    public static class Sender
    {
        public static async Task SendFileAsync(string token)
        {
            try
            {
                string[] parts = Script.DeconstructToken(token);
                if (parts.Length != 2)
                {
                    Console.WriteLine("Invalid token format.");
                    return;
                }
                string receiverIpAddress = parts[0];
                if (!IPAddress.TryParse(receiverIpAddress, out IPAddress ipAddress))
                {
                    Console.WriteLine("Invalid receiver IP address.");
                    return;
                }
                if (!int.TryParse(parts[1], out int receiverPort))
                {
                    Console.WriteLine("Invalid receiver port number.");
                    return;
                }
                using (TcpClient client = new TcpClient())
                {
                    await client.ConnectAsync(receiverIpAddress, receiverPort);
                    Console.WriteLine("Warning! You must enter path like this: C:\\Users\\hyper\\Downloads\\data.zip");
                    Console.Write("Enter path: ");
                    string filePath = Console.ReadLine();
                    byte[] fileBytes = File.ReadAllBytes(filePath);
                    byte[] sharedSecret = PerformKeyExchange(client);
                    byte[] encryptionKey = DeriveKey(sharedSecret);
                    byte[] encryptedFileBytes = AesGcmEncrypt(fileBytes, encryptionKey);
                    byte[] signature = SignData(encryptedFileBytes);
                    byte[] dataToSend = CombineBytes(signature, encryptedFileBytes);
                    using (NetworkStream stream = client.GetStream())
                    {
                        await stream.WriteAsync(dataToSend, 0, dataToSend.Length);
                    }
                    Console.WriteLine("File sent successfully.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }
        }

        private static byte[] PerformKeyExchange(TcpClient client)
        {
            int dhKeySize = 2048;
            int dhCertainty = 100;
            DHParametersGenerator generator = new DHParametersGenerator();
            generator.Init(dhKeySize, dhCertainty, new SecureRandom());
            DHParameters parameters = generator.GenerateParameters();
            AsymmetricCipherKeyPair keyPair = GenerateKeyPair(parameters);
            byte[] publicKeyBytes = ((DHPublicKeyParameters)keyPair.Public).Y.ToByteArray();
            byte[] parametersBytes = parameters.P.ToByteArray();
            byte[] dataToSend = CombineBytes(parametersBytes, publicKeyBytes);
            using (NetworkStream stream = client.GetStream())
            {
                stream.Write(dataToSend, 0, dataToSend.Length);
            }
            byte[] receivedData = new byte[2048];
            int bytesRead = client.GetStream().Read(receivedData, 0, receivedData.Length);
            byte[] receivedPublicKeyBytes = new byte[bytesRead];
            Buffer.BlockCopy(receivedData, 0, receivedPublicKeyBytes, 0, bytesRead);
            DHPrivateKeyParameters privateKey = (DHPrivateKeyParameters)keyPair.Private;
            DHPublicKeyParameters receivedPublicKey = new DHPublicKeyParameters(new BigInteger(receivedPublicKeyBytes), parameters);
            IBasicAgreement agreement = AgreementUtilities.GetBasicAgreement("DH");
            agreement.Init(privateKey);
            return agreement.CalculateAgreement(receivedPublicKey).ToByteArray();
        }

        private static AsymmetricCipherKeyPair GenerateKeyPair(DHParameters parameters)
        {
            DHBasicKeyPairGenerator keyPairGenerator = new DHBasicKeyPairGenerator();
            keyPairGenerator.Init(new DHKeyGenerationParameters(new SecureRandom(), parameters));
            return keyPairGenerator.GenerateKeyPair();
        }

        private static byte[] DeriveKey(byte[] sharedSecret)
        {
            int keySizeInBytes = 32;
            byte[] salt = GenerateRandomSalt();
            HkdfBytesGenerator hkdfGenerator = new HkdfBytesGenerator(new Sha256Digest());
            HkdfParameters hkdfParams = new HkdfParameters(sharedSecret, salt, null);
            hkdfGenerator.Init(hkdfParams);
            byte[] derivedKey = new byte[keySizeInBytes];
            hkdfGenerator.GenerateBytes(derivedKey, 0, derivedKey.Length);
            return derivedKey;
        }

        private static byte[] GenerateRandomSalt()
        {
            int saltSizeInBytes = 32;
            byte[] salt = new byte[saltSizeInBytes];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }
            return salt;
        }

        private static byte[] SignData(byte[] data)
        {
            RsaKeyPairGenerator rsaKeyPairGenerator = new RsaKeyPairGenerator();
            rsaKeyPairGenerator.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            AsymmetricCipherKeyPair keyPair = rsaKeyPairGenerator.GenerateKeyPair();
            ISigner signer = SignerUtilities.GetSigner("SHA256withRSA");
            signer.Init(true, keyPair.Private);
            signer.BlockUpdate(data, 0, data.Length);
            return signer.GenerateSignature();
        }

        private static byte[] CombineBytes(byte[] first, byte[] second)
        {
            byte[] combined = new byte[first.Length + second.Length];
            Buffer.BlockCopy(first, 0, combined, 0, first.Length);
            Buffer.BlockCopy(second, 0, combined, first.Length, second.Length);
            return combined;
        }

        private static byte[] AesGcmEncrypt(byte[] plaintext, byte[] key)
        {
            int ivSizeInBytes = 12;
            byte[] iv = new byte[ivSizeInBytes];
            var rng = new SecureRandom();
            rng.NextBytes(iv);
            KeyParameter keyParam = new KeyParameter(key);
            ParametersWithIV parameters = new ParametersWithIV(keyParam, iv);
            GcmBlockCipher cipher = new GcmBlockCipher(new AesFastEngine());
            cipher.Init(true, parameters);
            byte[] ciphertext = new byte[cipher.GetOutputSize(plaintext.Length)];
            int len = cipher.ProcessBytes(plaintext, 0, plaintext.Length, ciphertext, 0);
            cipher.DoFinal(ciphertext, len);
            byte[] encryptedData = new byte[iv.Length + ciphertext.Length];
            Buffer.BlockCopy(iv, 0, encryptedData, 0, iv.Length);
            Buffer.BlockCopy(ciphertext, 0, encryptedData, iv.Length, ciphertext.Length);
            return encryptedData;
        }
    }

    public static class Receiver
    {
        public static async Task ReceiveFileAsync(string token)
        {
            try
            {
                string[] parts = Script.DeconstructToken(token);
                if (parts.Length != 2)
                {
                    Console.WriteLine("Invalid token format.");
                    return;
                }
                string senderIpAddress = parts[0];
                if (!IPAddress.TryParse(senderIpAddress, out IPAddress ipAddress))
                {
                    Console.WriteLine("Invalid sender IP address.");
                    return;
                }
                if (!int.TryParse(parts[1], out int senderPort))
                {
                    Console.WriteLine("Invalid sender port number.");
                    return;
                }
                TcpListener listener = new TcpListener(ipAddress, senderPort);
                listener.Start();
                Console.WriteLine("Waiting for sender to connect...");
                using (TcpClient client = await listener.AcceptTcpClientAsync())
                {
                    using (NetworkStream stream = client.GetStream())
                    {
                        Console.WriteLine("Sender connected.");
                        byte[] sharedSecret = PerformKeyExchange(client);
                        byte[] decryptionKey = DeriveKey(sharedSecret);
                        byte[] receivedData = new byte[client.ReceiveBufferSize];
                        int bytesRead = await stream.ReadAsync(receivedData, 0, receivedData.Length);
                        byte[] signature = new byte[256];
                        byte[] encryptedFileBytes = new byte[bytesRead - 256];
                        Buffer.BlockCopy(receivedData, 0, signature, 0, signature.Length);
                        Buffer.BlockCopy(receivedData, signature.Length, encryptedFileBytes, 0, encryptedFileBytes.Length);
                        if (VerifySignature(encryptedFileBytes, signature))
                        {
                            byte[] decryptedFileBytes = AesGcmDecrypt(encryptedFileBytes, decryptionKey);
                            Console.WriteLine("Warning! You must enter path like this: C:\\Users\\hyper\\Downloads\\data.zip");
                            Console.Write("Enter path: ");
                            string savePath = Console.ReadLine();
                            File.WriteAllBytes(savePath, decryptedFileBytes);
                            Console.WriteLine("File received and saved successfully.");
                            Console.WriteLine("Press any key to close.");
                            Console.ReadKey();
                        }
                        else
                        {
                            Console.WriteLine("Signature verification failed. File integrity compromised.");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }
        }

        private static byte[] PerformKeyExchange(TcpClient client)
        {
            byte[] receivedData = new byte[2048];
            int bytesRead = client.GetStream().Read(receivedData, 0, receivedData.Length);
            byte[] receivedParametersBytes = new byte[bytesRead / 2];
            byte[] receivedPublicKeyBytes = new byte[bytesRead / 2];
            Buffer.BlockCopy(receivedData, 0, receivedParametersBytes, 0, bytesRead / 2);
            Buffer.BlockCopy(receivedData, bytesRead / 2, receivedPublicKeyBytes, 0, bytesRead / 2);
            BigInteger p = new BigInteger(receivedParametersBytes);
            DHParameters parameters = new DHParameters(p, BigInteger.ValueOf(2));
            AsymmetricCipherKeyPair keyPair = GenerateKeyPair(parameters);
            byte[] publicKeyBytes = ((DHPublicKeyParameters)keyPair.Public).Y.ToByteArray();
            using (NetworkStream stream = client.GetStream())
            {
                stream.Write(publicKeyBytes, 0, publicKeyBytes.Length);
            }
            DHPublicKeyParameters receivedPublicKey = new DHPublicKeyParameters(new BigInteger(receivedPublicKeyBytes), parameters);
            DHPrivateKeyParameters privateKey = (DHPrivateKeyParameters)keyPair.Private;
            IBasicAgreement agreement = AgreementUtilities.GetBasicAgreement("DH");
            agreement.Init(privateKey);
            return agreement.CalculateAgreement(receivedPublicKey).ToByteArray();
        }

        private static AsymmetricCipherKeyPair GenerateKeyPair(DHParameters parameters)
        {
            DHBasicKeyPairGenerator keyPairGenerator = new DHBasicKeyPairGenerator();
            keyPairGenerator.Init(new DHKeyGenerationParameters(new SecureRandom(), parameters));
            return keyPairGenerator.GenerateKeyPair();
        }

        private static bool VerifySignature(byte[] data, byte[] signature)
        {
            RsaKeyPairGenerator rsaKeyPairGenerator = new RsaKeyPairGenerator();
            rsaKeyPairGenerator.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            AsymmetricCipherKeyPair keyPair = rsaKeyPairGenerator.GenerateKeyPair();
            ISigner signer = SignerUtilities.GetSigner("SHA256withRSA");
            signer.Init(false, keyPair.Public);
            signer.BlockUpdate(data, 0, data.Length);
            return signer.VerifySignature(signature);
        }

        private static byte[] DeriveKey(byte[] sharedSecret)
        {
            byte[] salt = GenerateRandomSalt();
            HkdfBytesGenerator hkdfGenerator = new HkdfBytesGenerator(new Sha256Digest());
            HkdfParameters hkdfParams = new HkdfParameters(sharedSecret, salt, null);
            hkdfGenerator.Init(hkdfParams);
            byte[] derivedKey = new byte[32];
            hkdfGenerator.GenerateBytes(derivedKey, 0, derivedKey.Length);
            return derivedKey;
        }

        private static byte[] GenerateRandomSalt()
        {
            byte[] salt = new byte[32];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }
            return salt;
        }

        private static byte[] AesGcmDecrypt(byte[] encryptedData, byte[] key)
        {
            byte[] iv = new byte[12];
            Buffer.BlockCopy(encryptedData, 0, iv, 0, iv.Length);
            byte[] ciphertext = new byte[encryptedData.Length - iv.Length];
            Buffer.BlockCopy(encryptedData, iv.Length, ciphertext, 0, ciphertext.Length);
            KeyParameter keyParam = new KeyParameter(key);
            ParametersWithIV parameters = new ParametersWithIV(keyParam, iv);
            GcmBlockCipher cipher = new GcmBlockCipher(new AesFastEngine());
            cipher.Init(false, parameters);
            byte[] plaintext = new byte[cipher.GetOutputSize(ciphertext.Length)];
            int len = cipher.ProcessBytes(ciphertext, 0, ciphertext.Length, plaintext, 0);
            cipher.DoFinal(plaintext, len);
            return plaintext;
        }
    }
}
