using System.IO.Pipes;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

public sealed class BitwardenVault : IDisposable
{
    private readonly string AppId = $"{typeof(BitwardenVault).Name}:{Guid.NewGuid().ToString()}";

    private const int ConnectTimeoutMs = 3_000;

    private static int sequenceCounter;

    private DataJson dataJson;
    private byte[] userKey;

    public BitwardenVault()
    {
        dataJson = new DataJson();
    }

    public JsonElement GetItem(string itemId) => this.dataJson.GetItem(itemId);

    public string GetLoginProperty(JsonElement item, string name)
    {
        if (item.TryGetProperty("key", out var keyElement) == true &&
            item.TryGetProperty("login", out var loginElement) == true)
        {
            var keyBytes = BitwardenEncryption.DecryptBytes(keyElement.ToString(), this.userKey);
            return GetItemProperty(loginElement, name, encrypted: true, keyBytes);
        }

        return null;
    }

    private string PipeName
    {
        get
        {
            string homeFolder = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(homeFolder));

            string hex = Convert.ToBase64String(hash).Replace("+", "-").Replace("/", "_").TrimEnd('=');

            return $@"{hex}.s.bw";
        }
    }

    private IpcSession CreateIpcSession()
    {
        var userId = this.dataJson.GetActiveUserId();

        return new IpcSession(this.AppId, userId);
    }

    public void Unlock()
    {
        using var session = CreateIpcSession();
        Console.WriteLine($"Connecting to Bitwarden desktop app at {this.PipeName}...");
        session.Connect(this.PipeName, BitwardenVault.ConnectTimeoutMs);
        session.Handshake();
        this.userKey = session.BiometricUnlock() ?? throw new BitwardenException("Login failed", new AuthenticationException());
    }

    public string GetItemProperty(JsonElement item, string name, bool encrypted = true, byte[] itemKeyBytes = null)
    {
        if (item.TryGetProperty(name, out var propElement) == true)
        {
            if (encrypted && itemKeyBytes is not null)
            {
                //var itemKeyString = item.Value.GetProperty("key").GetString();
                //var itemKey = VaultCrypto.DecryptBytes(itemKeyString, this.userKey);
                var itemString = propElement.GetString();
                var itemValue = BitwardenEncryption.Decrypt(itemString, itemKeyBytes);
                return itemValue;
            }
        }
        return null;
    }

    public string GenerateTotp(JsonElement item)
    {
        var totpSecret = GetLoginProperty(item, "totp");
        if (totpSecret == null) return null;
        var totp = BitwardenEncryption.GenerateTotp(totpSecret);

        return totp;
    }

    public static string GenerateTotp(string totpSecret) => BitwardenEncryption.GenerateTotp(totpSecret);

    private sealed class IpcSession : IDisposable
    {
        private string appId;
        private string userId;
        private NamedPipeClientStream pipe;
        private BinaryReader reader;
        private BinaryWriter writer;
        private BitwardenEncryption crypto;

        public IpcSession(string appId, string userId)
        {
            this.appId = appId;
            this.userId = userId;
        }

        public void Connect(string pipeName, int timeoutMs)
        {
            this.pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            try
            {
                this.pipe.Connect(timeoutMs);
            }
            catch (Exception ex)
            {
                throw new BitwardenException(
                    "Bitwarden desktop app is not running or pipe is unavailable. " +
                    "Make sure the app is open and Settings → Browser integration is enabled.",
                    ex);
            }

            this.reader = new BinaryReader(this.pipe, Encoding.UTF8, leaveOpen: true);
            this.writer = new BinaryWriter(this.pipe, Encoding.UTF8, leaveOpen: true);
        }

        public void Handshake()
        {
            using var rsa = RSA.Create(2048);
            byte[] pubKeySpki = rsa.ExportSubjectPublicKeyInfo();

            var messageId = NextId();

            var setupMsg = new JsonObject
            {
                ["command"] = "setupEncryption",
                ["publicKey"] = Convert.ToBase64String(pubKeySpki),
                ["userId"] = this.userId,
                ["messageId"] = messageId,
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
            };

            SendRaw(setupMsg);

            JsonObject reply = ReceiveRaw();
            if (reply == null)
                throw new BitwardenException("Desktop app closed connection during handshake.");

            string sharedSecretB64 = reply["sharedSecret"] != null
                ? reply["sharedSecret"].GetValue<string>()
                : null;
            if (string.IsNullOrEmpty(sharedSecretB64))
                throw new BitwardenException($"setupEncryption reply missing sharedKey. Got: {reply}");

            byte[] encSharedSecret = Convert.FromBase64String(sharedSecretB64);
            byte[] sharedSecret;
            try
            {
                sharedSecret = rsa.Decrypt(encSharedSecret, RSAEncryptionPadding.OaepSHA1);
            }
            catch (CryptographicException ex)
            {
                throw new BitwardenException(
                    "Failed to decrypt sharedKey — RSA-OAEP decryption error.", ex);
            }

            if (sharedSecret.Length != 64)
                throw new BitwardenException(
                    $"Unexpected shared secret length: {sharedSecret.Length} (expected 64).");

            this.crypto = new BitwardenEncryption(sharedSecret);

            CryptographicOperations.ZeroMemory(sharedSecret);
        }

        public byte[] BiometricUnlock()
        {
            EnsureCrypto();

            var userId = this.userId;
            if (userId == null)
                throw new BitwardenException(
                    "Could not determine active userId from Bitwarden data.json. " +
                    "Make sure Bitwarden is logged in.");

            var msgId = NextId();
            var message = new JsonObject
            {
                ["messageId"] = msgId,
                ["command"] = "getBiometricsStatusForUser",
                ["userId"] = userId,
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
            };
            SendEncrypted(message);
            var statusResponse = ReceiveEncrypted();
            if (statusResponse["messageId"]?.GetValue<int>() != msgId)
                throw new BitwardenException($"Mismatched messageId in biometrics status response. Expected {msgId}, got {statusResponse["messageId"]}.");

            var available = statusResponse["response"]?.GetValue<int>() == 0;
            if (!available) return null;

            msgId = NextId();
            message = new JsonObject
            {
                ["messageId"] = msgId,
                ["command"] = "unlockWithBiometricsForUser",
                ["userId"] = userId,
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
            };
            SendEncrypted(message);
            var unlockResponse = ReceiveEncrypted();

            bool success = unlockResponse["response"].GetValue<bool>();
            if (!success) return null;

            var userKey = unlockResponse["userKeyB64"].GetValue<string>();
            var userKeyBytes = Convert.FromBase64String(userKey);

            return userKeyBytes;
        }

        private void SendEncrypted(JsonObject message)
        {
            string json = message.ToJsonString();
            string encryptedString = this.crypto.Encrypt(json, out var encryptionType, out var iv, out var data, out var mac);

            var encryptedMessage = new JsonObject
            {
                //["encryptionType"] = encryptionType,
                ["encryptedString"] = encryptedString,
                //["iv"] = iv,
                //["data"] = data,
                //["mac"] = mac
            };

            SendRaw(encryptedMessage);
        }

        private JsonObject ReceiveEncrypted()
        {
            JsonObject encryptedReponse = ReceiveRaw();

            var message = encryptedReponse["message"];

            if (message["encryptionType"].GetValue<int>() != 2) throw new NotSupportedException();

            var encryptedString = message["encryptedString"].GetValue<string>();

            var encryptionType = message["encryptionType"].GetValue<int>();
            var iv = message["iv"].GetValue<string>();
            var encryptedData = message["data"].GetValue<string>();
            var mac = message["mac"].GetValue<string>();

            var json = this.crypto.Decrypt(encryptionType, iv, encryptedData, mac);

            Console.WriteLine("recv decrypted: " + json);

            return JsonObject.Parse(json).AsObject();
        }

        private void SendRaw(JsonObject msg)
        {
            var envelope = new JsonObject
            {
                ["appId"] = this.appId,
                ["message"] = msg
            };
            var json = envelope.ToJsonString();
            var jsonBytes = Encoding.UTF8.GetBytes(json);

            this.writer.Write((uint)jsonBytes.Length);
            this.writer.Write(jsonBytes);
            this.writer.Flush();
            this.pipe.Flush();

            Console.WriteLine($"send {jsonBytes.Length}: {envelope.ToJsonString()}");
        }

        private JsonObject ReceiveRaw()
        {
            uint byteCount = this.reader.ReadUInt32();
            byte[] jsonBytes = this.reader.ReadBytes((int)byteCount);
            string json = Encoding.UTF8.GetString(jsonBytes);

            Console.WriteLine($"recv {byteCount}: {json}");

            JsonNode message = JsonNode.Parse(json);
            if (message == null)
                throw new BitwardenException("Received null JSON from pipe.");

            return message.AsObject();
        }

        private void EnsureCrypto()
        {
            if (this.crypto == null)
                throw new InvalidOperationException(
                    "Handshake not completed. Call Handshake() before sending commands.");
        }

        public void Dispose()
        {
            this.writer?.Dispose();
            this.reader?.Dispose();
            this.pipe?.Dispose();
        }
    }

    private sealed class BitwardenEncryption
    {
        private readonly byte[] _aesKey;
        private readonly byte[] _macKey;

        public BitwardenEncryption(byte[] sharedSecret)
        {
            _aesKey = sharedSecret[..32];
            _macKey = sharedSecret[32..];
        }

        public string Encrypt(string message, out int encryptionType, out string ivString, out string dataString, out string macString)
        {
            byte[] data = Encoding.UTF8.GetBytes(message);

            using var aes = Aes.Create();
            aes.Key = _aesKey;
            aes.GenerateIV();
            byte[] iv = aes.IV;
            byte[] cipher = aes.EncryptCbc(data, iv, PaddingMode.PKCS7);

            byte[] macInput = [.. iv, .. cipher];
            using var hmac = new HMACSHA256(_macKey);
            byte[] mac = hmac.ComputeHash(macInput);

            encryptionType = 2; // AesCbc256_HmacSha256_B64
            ivString = Convert.ToBase64String(iv);
            dataString = Convert.ToBase64String(cipher);
            macString = Convert.ToBase64String(mac);

            return $"{encryptionType}.{ivString}|{dataString}|{macString}";
        }

        public string Decrypt(string encryptedString)
        {
            var parts = encryptedString.Split('|');
            var parts2 = parts[0].Split('.');
            int encryptionType = int.Parse(parts2[0]);
            var iv = parts2[1];
            var data = parts[1];
            var mac = parts[2];

            return Decrypt(encryptionType, iv, data, mac);
        }

        public static byte[] DecryptBytes(string encryptedString, byte[] key)
        {
            // Split "2.iv|data|mac"
            var dot = encryptedString.IndexOf('.');
            var type = encryptedString.Substring(0, dot);

            if (type != "2")
                throw new NotSupportedException($"EncString type {type}");

            var parts = encryptedString[(dot + 1)..].Split('|');

            byte[] iv = Convert.FromBase64String(parts[0]);
            byte[] cipher = Convert.FromBase64String(parts[1]);
            byte[] mac = Convert.FromBase64String(parts[2]);

            byte[] aesKey = key[..32];
            byte[] hmacKey = key[32..64];

            // Verify MAC
            using (var hmac = new HMACSHA256(hmacKey))
            {
                byte[] macInput = new byte[iv.Length + cipher.Length];

                Buffer.BlockCopy(iv, 0, macInput, 0, iv.Length);
                Buffer.BlockCopy(cipher, 0, macInput, iv.Length, cipher.Length);

                byte[] computed = hmac.ComputeHash(macInput);

                if (!CryptographicOperations.FixedTimeEquals(computed, mac))
                    throw new CryptographicException("MAC verification failed");
            }

            using var aes = Aes.Create();

            aes.Key = aesKey;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using var decryptor = aes.CreateDecryptor();

            byte[] decryptedBytes = decryptor.TransformFinalBlock(cipher, 0, cipher.Length);

            return decryptedBytes;
        }

        public static string Decrypt(string encryptedString, byte[] key)
        {
            return Encoding.UTF8.GetString(DecryptBytes(encryptedString, key));
        }

        public string Decrypt(int encryptionType, string ivString, string dataString, string macString)
        {
            if (encryptionType != 2) throw new NotSupportedException();

            byte[] iv = Convert.FromBase64String(ivString);
            byte[] cipher = Convert.FromBase64String(dataString);
            byte[] mac = Convert.FromBase64String(macString);

            byte[] macInput = [.. iv, .. cipher];
            using var hmac = new HMACSHA256(_macKey);
            byte[] expected = hmac.ComputeHash(macInput);

            if (!CryptographicOperations.FixedTimeEquals(mac, expected))
                throw new BitwardenException("Encrypted message MAC verification failed.");

            using var aes = Aes.Create();
            aes.Key = _aesKey;
            byte[] plain = aes.DecryptCbc(cipher, iv, PaddingMode.PKCS7);
            return Encoding.UTF8.GetString(plain);
        }

        private static byte[] Base32Decode(string input)
        {
            const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

            input = input
                .Trim()
                .Replace("=", "")
                .Replace(" ", "")
                .ToUpperInvariant();

            List<byte> output = new();

            int buffer = 0;
            int bitsLeft = 0;

            foreach (char c in input)
            {
                int value = alphabet.IndexOf(c);

                if (value < 0)
                    throw new FormatException($"Invalid Base32 character: {c}");

                buffer = (buffer << 5) | value;
                bitsLeft += 5;

                while (bitsLeft >= 8)
                {
                    bitsLeft -= 8;
                    output.Add((byte)((buffer >> bitsLeft) & 0xFF));
                }
            }

            return output.ToArray();
        }

        public static string GenerateTotp(string secret, int digits = 6) => GenerateTotp(Base32Decode(secret), digits);

        public static string GenerateTotp(byte[] secret, int digits = 6)
        {
            long timestep = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;

            byte[] counter = BitConverter.GetBytes(timestep);

            if (BitConverter.IsLittleEndian)
                Array.Reverse(counter);

            using var hmac = new HMACSHA1(secret);

            byte[] hash = hmac.ComputeHash(counter);

            int offset = hash[^1] & 0x0F;

            int binary =
                ((hash[offset] & 0x7F) << 24) |
                ((hash[offset + 1] & 0xFF) << 16) |
                ((hash[offset + 2] & 0xFF) << 8) |
                (hash[offset + 3] & 0xFF);

            int otp = binary % (int)Math.Pow(10, digits);

            return otp.ToString(new string('0', digits));
        }
    }

    private class DataJson : IDisposable
    {
        private JsonDocument doc;
        private string userId;

        private JsonElement ciphersElement;

        private static readonly string[] SearchPaths =
        [
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Bitwarden", "data.json"),
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Bitwarden CLI", "data.json")
        ];

        public DataJson()
        {
            LoadJson();
        }

        public void Dispose()
        {
            this.doc?.Dispose();
            this.userId = null;
        }

        private void LoadJson()
        {
            foreach (string path in SearchPaths)
            {
                if (!File.Exists(path)) continue;
                try
                {
                    this.doc = JsonDocument.Parse(File.ReadAllText(path));

                    var root = this.doc.RootElement;

                    if (root.TryGetProperty("global_account_activeAccountId", out JsonElement idElement))
                    {
                        this.userId = idElement.GetString();

                        this.ciphersElement = root.GetProperty($"user_{userId}_ciphers_ciphers");
                    }
                }
                catch { /* corrupt / locked file — try next path */ }
            }
        }

        public string GetActiveUserId() => this.userId ?? throw new InvalidDataException();

        public JsonElement GetItem(string itemId)
        {
            return this.ciphersElement.TryGetProperty(itemId, out var propertyElement) ? propertyElement : default;
        }
    }

    private static int NextId() => Interlocked.Increment(ref BitwardenVault.sequenceCounter);

    public void Dispose()
    {
        if (this.userKey is not null) CryptographicOperations.ZeroMemory(this.userKey);
        this.dataJson?.Dispose();
    }
}

/// <summary>
/// Thrown when a Bitwarden vault operation fails.
/// </summary>
public sealed class BitwardenException : Exception
{
    public BitwardenException(string message) : base(message) { }
    public BitwardenException(string message, Exception inner) : base(message, inner) { }
}
