// Простори імен BouncyCastle для криптографії
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Security.Cryptography;
using ChaCha20Poly1305 = Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305;

namespace SecureVideoApp
{
    /// <summary>
    /// Клас, що реалізує гібридну схему шифрування відеопотоку.
    /// Key Exchange: ECDH (X25519) - забезпечує Perfect Forward Secrecy.
    /// Stream Cipher: ChaCha20 - висока продуктивність.
    /// MAC: Poly1305 - гарантія цілісності даних.
    /// </summary>
    public class HybridVideoEncryptor
    {
        // Константи протоколу
        private const int KeySize = 32;       // 256 біт (розмір ключа ChaCha20 та X25519)
        private const int StreamNonceSize = 12; // 96 біт (рекомендація RFC 8439)
        private const int MacTagSize = 16;      // 128 біт (розмір тегу Poly1305)

        /// <summary>
        /// Генерація тимчасової (ефемерної) пари ключів для одного сеансу.
        /// </summary>
        private AsymmetricCipherKeyPair GenerateEphemeralKeyPair()
        {
            var generator = new X25519KeyPairGenerator();
            generator.Init(new KeyGenerationParameters(new SecureRandom(), 256));
            return generator.GenerateKeyPair();
        }

        /// <summary>
        /// Математичне обчислення спільного секрету (Shared Secret) на основі ключів двох сторін.
        /// Використовує хешування SHA-256 (KDF) для отримання рівномірного ключа шифрування.
        /// </summary>
        private byte[] DeriveSessionKey(AsymmetricKeyParameter privateKey, AsymmetricKeyParameter publicKey)
        {
            // 1. Обчислюємо "сирий" секрет через Curve25519
            var agreement = new X25519Agreement();
            agreement.Init(privateKey);

            byte[] sharedSecret = new byte[agreement.AgreementSize];
            agreement.CalculateAgreement(publicKey, sharedSecret, 0);

            // 2. KDF: Проганяємо через SHA-256, щоб отримати криптостійкий ключ для ChaCha20
            Sha256Digest hash = new Sha256Digest();
            byte[] derivedKey = new byte[hash.GetDigestSize()];
            hash.BlockUpdate(sharedSecret, 0, sharedSecret.Length);
            hash.DoFinal(derivedKey, 0);

            return derivedKey;
        }

        /// <summary>
        /// Шифрує відеофайл.
        /// </summary>
        /// <param name="inputPath">Шлях до вихідного файлу.</param>
        /// <param name="outputPath">Куди зберегти результат.</param>
        /// <param name="receiverPublicKeyBytes">Публічний ключ отримувача (X25519).</param>
        /// <param name="reporter">Інтерфейс для логування в UI.</param>
        /// <param name="onDataProcessed">Callback для візуалізації шуму (ентропії).</param>
        public void EncryptVideo(
            string inputPath,
            string outputPath,
            byte[] receiverPublicKeyBytes,
            IProgress<string> reporter,
            Action<byte[]> onDataProcessed = null)
        {
            reporter.Report($"[CRYPTO] Генерація одноразових ключів (Ephemeral Keys)...");

            // 1. Генеруємо пару ключів спеціально для цього файлу (Forward Secrecy)
            var ephemeralKeyPair = GenerateEphemeralKeyPair();
            var ephemeralPrivateKey = (X25519PrivateKeyParameters)ephemeralKeyPair.Private;
            var ephemeralPublicKey = (X25519PublicKeyParameters)ephemeralKeyPair.Public;

            // 2. Обчислюємо сесійний ключ: (Наш Приватний + Чужий Публічний)
            var receiverPublicKey = new X25519PublicKeyParameters(receiverPublicKeyBytes, 0);
            byte[] sessionKey = DeriveSessionKey(ephemeralPrivateKey, receiverPublicKey);

            // 3. Генеруємо унікальний Nonce
            byte[] nonce = new byte[StreamNonceSize];
            new SecureRandom().NextBytes(nonce);

            // 4. Налаштування ChaCha20-Poly1305
            var cipher = new ChaCha20Poly1305();
            var parameters = new AeadParameters(new KeyParameter(sessionKey), MacTagSize * 8, nonce, null);
            cipher.Init(true, parameters); // true = Encrypt

            // 5. Читання даних
            // Прим: У продакшені читати потрібно частинами (Stream), тут для прототипу читаємо все одразу.
            byte[] videoData = File.ReadAllBytes(inputPath);
            reporter.Report($"[IO] Завантажено {videoData.Length} байт. Шифруємо...");

            byte[] outputBuffer = new byte[cipher.GetOutputSize(videoData.Length)];

            // Процес шифрування
            int len = cipher.ProcessBytes(videoData, 0, videoData.Length, outputBuffer, 0);
            cipher.DoFinal(outputBuffer, len);

            // 6. Візуалізація ентропії (Callback в UI)
            if (onDataProcessed != null && outputBuffer.Length > 0)
            {
                // Відправляємо UI весь буфер або його початок для відмальовування "шуму"
                onDataProcessed(outputBuffer);
            }

            // 7. Збірка пакета та запис на диск
            // Формат файлу: [Len PubKey] + [PubKey] + [Nonce] + [Ciphertext + Tag]
            byte[] ephemeralPublicBytes = ephemeralPublicKey.GetEncoded();

            using (FileStream fs = new FileStream(outputPath, FileMode.Create))
            using (BinaryWriter bw = new BinaryWriter(fs))
            {
                bw.Write(ephemeralPublicBytes.Length);
                bw.Write(ephemeralPublicBytes); // Пишемо НАШ публічний ключ, щоб отримувач міг узгодити секрет
                bw.Write(nonce);
                bw.Write(outputBuffer);
            }

            reporter.Report($"[SUCCESS] Дані захищені та записані у {Path.GetFileName(outputPath)}");
        }

        /// <summary>
        /// Розшифровує відеофайл.
        /// </summary>
        /// <param name="encryptedPath">Зашифрований файл.</param>
        /// <param name="restoredPath">Куди зберегти відео.</param>
        /// <param name="receiverPrivateKeyBytes">Приватний ключ отримувача (X25519).</param>
        /// <param name="reporter">Логер.</param>
        public void DecryptVideo(string encryptedPath, string restoredPath, byte[] receiverPrivateKeyBytes, IProgress<string> reporter)
        {
            reporter.Report($"[IO] Виконується читання контейнера {Path.GetFileName(encryptedPath)}...");

            using (FileStream fs = new FileStream(encryptedPath, FileMode.Open))
            using (BinaryReader br = new BinaryReader(fs))
            {
                // 1. Парсинг заголовка
                int pubKeyLen = br.ReadInt32();
                byte[] senderEphemeralPublicBytes = br.ReadBytes(pubKeyLen);
                byte[] nonce = br.ReadBytes(StreamNonceSize);
                byte[] payload = br.ReadBytes((int)(fs.Length - fs.Position));

                // 2. Відновлення ключів
                var receiverPrivateKey = new X25519PrivateKeyParameters(receiverPrivateKeyBytes, 0);
                var senderEphemeralPublicKey = new X25519PublicKeyParameters(senderEphemeralPublicBytes, 0);

                reporter.Report($"[CRYPTO] Виконується узгодження ключів (ECDH)...");

                // 3. Обчислення того ж самого сесійного ключа
                // (Наш Приватний + Публічний ключ із заголовка файлу)
                byte[] sessionKey = DeriveSessionKey(receiverPrivateKey, senderEphemeralPublicKey);

                // 4. Налаштування ChaCha20-Poly1305
                var cipher = new ChaCha20Poly1305();
                var param = new AeadParameters(new KeyParameter(sessionKey), MacTagSize * 8, nonce, null);
                cipher.Init(false, param); // false = Decrypt

                byte[] result = new byte[cipher.GetOutputSize(payload.Length)];

                try
                {
                    // 5. Розшифрування та перевірка цілісності
                    int len = cipher.ProcessBytes(payload, 0, payload.Length, result, 0);
                    cipher.DoFinal(result, len); // Тут перевіряється Poly1305 Tag
                }
                catch (InvalidCipherTextException)
                {
                    // Це ключовий момент для безпеки: якщо хоч один біт змінено, ми не віддаємо дані.
                    reporter.Report($"[CRYPTO ERROR] Критична помилка! Порушена цілісність даних (MAC mismatch).");
                    throw new CryptographicException("Критична помилка: Порушена цілісність даних (MAC mismatch). Можливо, файл був модифікований!");
                }

                // 6. Збереження результату
                File.WriteAllBytes(restoredPath, result);
                reporter.Report($"[SUCCESS] Відео успішно відновлено та верифіковано.");
            }
        }
    }
}
