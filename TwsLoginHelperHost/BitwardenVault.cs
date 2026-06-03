using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Bitwarden.Vault;

/// <summary>
/// Communicates with the running Bitwarden desktop app over its named pipe IPC channel
/// to perform biometric (Windows Hello) unlock and vault lock operations.
///
/// The desktop app must be running with Settings → Browser integration enabled.
/// No credentials or keys are stored anywhere by this library.
/// </summary>
public sealed class BitwardenVault : IDisposable
{
    // node-ipc on Windows uses \\.\pipe\tmp-app.bitwarden
    private const string PipeName = "tmp-app.bitwarden";
    private const int ConnectTimeoutMs = 3_000;
    private const int UnlockTimeoutMs  = 120_000; // user needs time to do biometrics
    private const int LockTimeoutMs    = 10_000;

    private static int _sequenceCounter;

    public void Dispose() { }  // stateless — nothing to dispose

    // ── Public API ────────────────────────────────────────────────────────

    /// <summary>
    /// Triggers a biometric (Windows Hello) unlock via the Bitwarden desktop app.
    /// </summary>
    /// <returns>
    /// The BW_SESSION key (base64-encoded vault symmetric key) that can be passed
    /// to the <c>bw</c> CLI via <c>--session</c> or <c>$env:BW_SESSION</c>.
    /// </returns>
    /// <exception cref="BitwardenException">
    /// Thrown when the desktop app is not running, biometrics are declined,
    /// or any protocol error occurs.
    /// </exception>
    public string Unlock()
    {
        using var session = new IpcSession();
        session.Connect(PipeName, ConnectTimeoutMs);
        session.Handshake();
        return session.BiometricUnlock(UnlockTimeoutMs);
    }

    /// <summary>
    /// Sends a lock command to the Bitwarden desktop app, locking the vault.
    /// </summary>
    /// <exception cref="BitwardenException">
    /// Thrown when the desktop app is not running or fails to acknowledge the lock.
    /// </exception>
    public void Lock()
    {
        using var session = new IpcSession();
        session.Connect(PipeName, ConnectTimeoutMs);
        session.Handshake();
        session.LockVault(LockTimeoutMs);
    }

    // ── IPC session (private) ─────────────────────────────────────────────

    private sealed class IpcSession : IDisposable
    {
        private NamedPipeClientStream? _pipe;
        private StreamReader?          _reader;
        private StreamWriter?          _writer;
        private IpcCrypto?             _crypto;

        // ── Connection ────────────────────────────────────────────────────

        public void Connect(string pipeName, int timeoutMs)
        {
            _pipe = new NamedPipeClientStream(".", pipeName,
                PipeDirection.InOut, PipeOptions.None);
            try
            {
                _pipe.Connect(timeoutMs);
            }
            catch (Exception ex)
            {
                throw new BitwardenException(
                    "Bitwarden desktop app is not running or pipe is unavailable. " +
                    "Make sure the app is open and Settings → Browser integration is enabled.",
                    ex);
            }

            _reader = new StreamReader(_pipe, Encoding.UTF8, leaveOpen: true);
            _writer = new StreamWriter(_pipe, Encoding.UTF8, leaveOpen: true)
            {
                AutoFlush = true,
                NewLine   = "\n"
            };
        }

        // ── Handshake (setupEncryption) ───────────────────────────────────

        /// <summary>
        /// Performs the RSA key-exchange handshake. After this, all further
        /// messages are sent and received encrypted.
        /// </summary>
        public void Handshake()
        {
            // Generate an ephemeral RSA-2048 keypair for this session.
            using var rsa = RSA.Create(2048);
            byte[] pubKeySpki = rsa.ExportSubjectPublicKeyInfo();

            var setupMsg = new JsonObject
            {
                ["messageId"] = NextId(),
                ["command"]   = "setupEncryption",
                ["publicKey"] = Convert.ToBase64String(pubKeySpki)
            };

            // setupEncryption is the only plaintext message — send it directly.
            SendRaw(setupMsg);

            // The desktop app replies with { command: "setupEncryption", sharedKey: "<b64>" }
            // outside of any data envelope (also plaintext).
            JsonObject reply = ReceiveRaw(ConnectTimeoutMs)
                ?? throw new BitwardenException("Desktop app closed connection during handshake.");

            string? sharedKeyB64 = reply["sharedKey"]?.GetValue<string>();
            if (string.IsNullOrEmpty(sharedKeyB64))
                throw new BitwardenException(
                    $"setupEncryption reply missing sharedKey. Got: {reply}");

            // Decrypt the shared secret with our private key.
            byte[] encSharedSecret = Convert.FromBase64String(sharedKeyB64);
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

            _crypto = new IpcCrypto(sharedSecret);

            // Zero sensitive material now that it's been consumed.
            CryptographicOperations.ZeroMemory(sharedSecret);
        }

        // ── Commands ──────────────────────────────────────────────────────

        public string BiometricUnlock(int timeoutMs)
        {
            EnsureCrypto();

            string userId = DataJson.FindActiveUserId()
                ?? throw new BitwardenException(
                    "Could not determine active userId from Bitwarden data.json. " +
                    "Make sure Bitwarden is logged in.");

            string msgId = NextId();
            var inner = new JsonObject
            {
                ["messageId"] = msgId,
                ["command"]   = "biometricUnlock",
                ["userId"]    = userId
            };

            SendEncrypted(msgId, inner);

            // Desktop app will now prompt Windows Hello — wait up to timeoutMs.
            JsonObject plainReply = ReceiveEncrypted(timeoutMs, msgId)
                ?? throw new BitwardenException(
                    "Timed out waiting for biometricUnlock response. " +
                    "The user may have cancelled, or the desktop app is unresponsive.");

            string? response = plainReply["response"]?.GetValue<string>();
            if (response != "unlocked")
            {
                string reason = response ?? "(no response field)";
                throw new BitwardenException(
                    $"Biometric unlock was not successful. Desktop response: \"{reason}\".");
            }

            string? keyB64 = plainReply["keyB64"]?.GetValue<string>();
            if (string.IsNullOrEmpty(keyB64))
                throw new BitwardenException(
                    "Unlock succeeded but the response contained no keyB64.");

            return keyB64;
        }

        public void LockVault(int timeoutMs)
        {
            EnsureCrypto();

            string msgId = NextId();
            var inner = new JsonObject
            {
                ["messageId"] = msgId,
                ["command"]   = "lockVault"
            };

            SendEncrypted(msgId, inner);

            // The desktop app may reply with an acknowledgement, or may just
            // silently close the pipe after locking. Either is acceptable.
            // We give it a short window and treat silence as success.
            try
            {
                JsonObject? reply = ReceiveEncrypted(timeoutMs, msgId);
                // reply is informational — any response (or none) means the command was received.
            }
            catch (BitwardenException)
            {
                // Timeout or disconnect after sending lock is expected and fine.
            }
        }

        // ── Send / receive ────────────────────────────────────────────────

        private void SendEncrypted(string messageId, JsonObject inner)
        {
            string plaintext = inner.ToJsonString();
            string envelope  = _crypto!.Encrypt(plaintext);

            var outer = new JsonObject
            {
                ["messageId"]        = messageId,
                ["encryptedCommand"] = envelope
            };
            SendRaw(outer);
        }

        // Receive an encrypted reply whose messageId matches the expected one.
        // Discards unrelated messages (e.g. status broadcasts).
        private JsonObject? ReceiveEncrypted(int timeoutMs, string expectedMsgId)
        {
            DateTime deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
            while (DateTime.UtcNow < deadline)
            {
                int remaining = (int)(deadline - DateTime.UtcNow).TotalMilliseconds;
                if (remaining <= 0) break;

                JsonObject? outer = ReceiveRaw(remaining);
                if (outer is null) return null; // pipe closed

                // Prefer encryptedResponse, fall back to encryptedCommand
                string? enc = outer["encryptedResponse"]?.GetValue<string>()
                           ?? outer["encryptedCommand"]?.GetValue<string>();

                if (enc is null) continue; // unencrypted broadcast, skip

                string plaintext = _crypto!.Decrypt(enc);
                JsonObject inner = JsonSerializer.Deserialize<JsonObject>(plaintext)
                    ?? throw new BitwardenException("Failed to deserialize decrypted reply.");

                string? replyId = inner["messageId"]?.GetValue<string>();
                if (replyId == expectedMsgId || replyId is null)
                    return inner;

                // Different messageId — this is a concurrent broadcast; discard and loop.
            }
            return null; // timed out
        }

        // node-ipc on Windows wraps every message in { "type": "message", "data": <payload> }\n
        private void SendRaw(JsonObject msg)
        {
            var envelope = new JsonObject
            {
                ["type"] = "message",
                ["data"] = JsonNode.Parse(msg.ToJsonString())
            };
            _writer!.WriteLine(envelope.ToJsonString());
        }

        // Returns null on EOF/disconnect. Blocks until data arrives or timeoutMs elapses.
        private JsonObject? ReceiveRaw(int timeoutMs)
        {
            // NamedPipeClientStream is synchronous; we run the read on a task
            // so we can respect the timeout without blocking forever.
            var cts = new CancellationTokenSource(timeoutMs);
            try
            {
                string? line = Task.Run(() => _reader!.ReadLine(), cts.Token)
                                   .GetAwaiter().GetResult();

                if (line is null) return null;
                line = line.Trim();
                if (line.Length == 0) return null;

                JsonNode root = JsonNode.Parse(line)
                    ?? throw new BitwardenException("Received null JSON from pipe.");

                // Unwrap node-ipc envelope if present
                JsonNode? data = root["data"];
                return (data ?? root).AsObject();
            }
            catch (OperationCanceledException)
            {
                return null; // timeout
            }
        }

        private void EnsureCrypto()
        {
            if (_crypto is null)
                throw new InvalidOperationException(
                    "Handshake not completed. Call Handshake() before sending commands.");
        }

        public void Dispose()
        {
            _writer?.Dispose();
            _reader?.Dispose();
            _pipe?.Dispose();
        }
    }

    // ── Crypto (AES-256-CBC + HMAC-SHA256) ───────────────────────────────────
    //
    // Shared secret layout (64 bytes received from desktop app after RSA decrypt):
    //   [0..31]  → AES-256 key
    //   [32..63] → HMAC-SHA256 key
    //
    // Encrypted envelope format: "<base64 IV>|<base64 ciphertext>|<base64 HMAC>"
    // HMAC is computed over (IV || ciphertext).

    private sealed class IpcCrypto
    {
        private readonly byte[] _aesKey;
        private readonly byte[] _macKey;

        public IpcCrypto(byte[] sharedSecret)
        {
            _aesKey = sharedSecret[..32];
            _macKey = sharedSecret[32..];
        }

        public string Encrypt(string plaintext)
        {
            byte[] data = Encoding.UTF8.GetBytes(plaintext);

            using var aes = Aes.Create();
            aes.Key = _aesKey;
            aes.GenerateIV();
            byte[] iv     = aes.IV;
            byte[] cipher = aes.EncryptCbc(data, iv, PaddingMode.PKCS7);

            byte[] macInput = [.. iv, .. cipher];
            using var hmac  = new HMACSHA256(_macKey);
            byte[] mac      = hmac.ComputeHash(macInput);

            return $"{Convert.ToBase64String(iv)}|{Convert.ToBase64String(cipher)}|{Convert.ToBase64String(mac)}";
        }

        public string Decrypt(string envelope)
        {
            string[] parts = envelope.Split('|');
            if (parts.Length != 3)
                throw new BitwardenException($"Malformed encrypted envelope: \"{envelope}\"");

            byte[] iv     = Convert.FromBase64String(parts[0]);
            byte[] cipher = Convert.FromBase64String(parts[1]);
            byte[] mac    = Convert.FromBase64String(parts[2]);

            byte[] macInput  = [.. iv, .. cipher];
            using var hmac   = new HMACSHA256(_macKey);
            byte[] expected  = hmac.ComputeHash(macInput);

            if (!CryptographicOperations.FixedTimeEquals(mac, expected))
                throw new BitwardenException("Encrypted message MAC verification failed.");

            using var aes = Aes.Create();
            aes.Key = _aesKey;
            byte[] plain = aes.DecryptCbc(cipher, iv, PaddingMode.PKCS7);
            return Encoding.UTF8.GetString(plain);
        }
    }

    // ── data.json helper ─────────────────────────────────────────────────────
    //
    // Reads the active userId from whichever Bitwarden data.json is present.
    //
    // Newer layout (desktop app / browser extension, 2023+):
    //   { "global_account_activeUserId": "<userId>", "<userId>": { ... } }
    //
    // Older layout (some CLI versions):
    //   { "userId": "<userId>", ... }

    private static class DataJson
    {
        private static readonly string[] SearchPaths =
        [
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Bitwarden", "data.json"),
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Bitwarden CLI", "data.json"),
        ];

        public static string? FindActiveUserId()
        {
            foreach (string path in SearchPaths)
            {
                if (!File.Exists(path)) continue;
                try
                {
                    using var doc = JsonDocument.Parse(File.ReadAllText(path));
                    JsonElement root = doc.RootElement;

                    // New layout
                    if (root.TryGetProperty("global_account_activeUserId", out var newId))
                    {
                        string? id = newId.GetString();
                        if (!string.IsNullOrEmpty(id)) return id;
                    }

                    // Old layout
                    if (root.TryGetProperty("userId", out var oldId))
                    {
                        string? id = oldId.GetString();
                        if (!string.IsNullOrEmpty(id)) return id;
                    }
                }
                catch { /* corrupt / locked file — try next path */ }
            }
            return null;
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static string NextId() =>
        $"bv-{Interlocked.Increment(ref _sequenceCounter)}";
}

/// <summary>
/// Thrown when a Bitwarden vault operation fails.
/// </summary>
public sealed class BitwardenException : Exception
{
    public BitwardenException(string message) : base(message) { }
    public BitwardenException(string message, Exception inner) : base(message, inner) { }
}
