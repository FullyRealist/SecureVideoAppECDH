using AxWMPLib;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Drawing;
using System.Drawing.Imaging; // Для роботи з bitmap (шум)
using System.IO;
using System.Runtime.InteropServices; // Для Marshal.Copy
using System.Threading.Tasks;
using System.Windows.Forms;

namespace SecureVideoApp
{
    public partial class MainForm : Form
    {

        // == Дані програми ==
        private string selectedFilePath;
        private const string KeysFile = "ECDH.key"; // Файл для зберігання ключів

        // Ключі поточного користувача (X25519)
        private byte[] myPrivateKey;
        private byte[] myPublicKey;

        // Екземпляр нашого крипто-рушія
        private HybridVideoEncryptor encryptor = new HybridVideoEncryptor();

        public MainForm()
        {
            // Ініціалізація компонентів дизайнера (WMP створюється тут)
            InitializeComponent();

            // Завантаження або генерація ключів
            InitializeKeys();

            // Попереднє налаштування плеєра
            try
            {
                axWindowsMediaPlayer1.uiMode = "none"; // Прибираємо кнопки плеєра
                axWindowsMediaPlayer1.settings.autoStart = false;
                axWindowsMediaPlayer1.settings.volume = 0; // Щоб не заважало під час тестів
            }
            catch { /* Ігноруємо, якщо плеєр ще не завантажився */ }
        }

        private void CreateWindowsMediaPlayerControl()
        {
            axWindowsMediaPlayer1 = new AxWMPLib.AxWindowsMediaPlayer();
            ((System.ComponentModel.ISupportInitialize)axWindowsMediaPlayer1).BeginInit();
            axWindowsMediaPlayer1.Name = "axWindowsMediaPlayer1";
            axWindowsMediaPlayer1.Location = new Point(20, 70);
            axWindowsMediaPlayer1.Size = new Size(400, 300);
            this.Controls.Add(axWindowsMediaPlayer1);
            ((System.ComponentModel.ISupportInitialize)axWindowsMediaPlayer1).EndInit();
        }

        // == Логіка роботи з ключами ECDH ==
        private void InitializeKeys()
        {
            if (File.Exists(KeysFile))
            {
                try
                {
                    string[] lines = File.ReadAllLines(KeysFile);
                    myPublicKey = Convert.FromBase64String(lines[0]);
                    myPrivateKey = Convert.FromBase64String(lines[1]);
                    Log("[INFO] Пара ключів X25519 була успішно завантажена з диску");
                }
                catch
                {
                    Log("[WARN] Файл ключів було пошкоджено!");
                    Log("[INFO] Виконується генерація нової пари ключів...");
                    GenerateAndSaveKeys();
                }
            }
            else
            {
                GenerateAndSaveKeys();
            }
        }

        private void GenerateAndSaveKeys()
        {
            var gen = new X25519KeyPairGenerator();
            gen.Init(new KeyGenerationParameters(new SecureRandom(), 256));
            var pair = gen.GenerateKeyPair();

            var pubParams = (X25519PublicKeyParameters)pair.Public;
            var privParams = (X25519PrivateKeyParameters)pair.Private;

            myPublicKey = pubParams.GetEncoded();
            myPrivateKey = privParams.GetEncoded();

            File.WriteAllLines(KeysFile, new[] {
                Convert.ToBase64String(myPublicKey),
                Convert.ToBase64String(myPrivateKey)
            });
            Log("[READY] Нова пара ключів (X25519) була успішно згенерована");
        }

        // == Обробники подій ==

        private void BtnSelectFile_Click(object sender, EventArgs e)
        {
            using (OpenFileDialog ofd = new OpenFileDialog())
            {
                ofd.Filter = "Медіа файли|*.mp3;*.mp4;*.avi;*.mkv;*.wmv|Зашифровані медіа|*.enc|Усі файли|*.*";
                if (ofd.ShowDialog() == DialogResult.OK)
                {
                    selectedFilePath = ofd.FileName;
                    Log($"Обрано файл: {Path.GetFileName(selectedFilePath)}");

                    bool isEncrypted = selectedFilePath.EndsWith(".enc");
                    btnEncrypt.Enabled = !isEncrypted;
                    btnDecrypt.Enabled = isEncrypted;

                    if (!isEncrypted)
                    {
                        // Завантажуємо прев'ю відео
                        axWindowsMediaPlayer1.URL = selectedFilePath;
                        axWindowsMediaPlayer1.Ctlcontrols.pause(); // Тільки перший кадр
                    }
                    else
                    {
                        axWindowsMediaPlayer1.Ctlcontrols.stop();
                        axWindowsMediaPlayer1.URL = "";
                        pbNoise.Image = null; // Очищаємо шум
                    }
                }
            }
        }

        private async void BtnEncrypt_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrEmpty(selectedFilePath)) return;

            string outputFile = selectedFilePath + ".enc";
            var reporter = GetProgressReporter();

            Log("[INFO] Почато процесс шифрування");

            // Запускаємо відео, щоб показати "ЩО" ми шифруємо
            axWindowsMediaPlayer1.Ctlcontrols.play();

            await RunCryptoTask(() => encryptor.EncryptVideo(
                selectedFilePath,
                outputFile,
                myPublicKey, // У реальній схемі тут був би Public Key отримувача
                reporter,
                // Callback для візуалізації (викликається з глибин шифратора)
                (chunk) => UpdateNoiseVisualization(chunk)
            ));

            Log("[INFO] Процес шифрування завершено");
            axWindowsMediaPlayer1.Ctlcontrols.pause();
            Log("Відтворення було призупинено");
        }

        private async void BtnDecrypt_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrEmpty(selectedFilePath)) return;

            string outputFile = selectedFilePath.Replace(".enc", "_restored.mp4");
            // Захист від перезапису, якщо імена збігаються
            if (outputFile == selectedFilePath) outputFile += ".restored.mp4";

            var reporter = GetProgressReporter();

            Log("[INFO] Почато процесс розшифрування");
            // pbNoise.Image = null; // Очищаємо екран шуму

            await RunCryptoTask(() => encryptor.DecryptVideo(
                selectedFilePath,
                outputFile,
                myPrivateKey,
                reporter
            ));

            if (File.Exists(outputFile))
            {
                Log("[INFO] Завантаження та відтворення розшифрованого відео");
                axWindowsMediaPlayer1.URL = outputFile;
                axWindowsMediaPlayer1.Ctlcontrols.play();
                Log("[DONE] Операцію успішно завершено!");
            }
        }

        // == Допоміжні методи ==

        // Метод відмальовування шуму (Ентропії)
        private void UpdateNoiseVisualization(byte[] data)
        {
            // Для візуалізації достатньо невеликої роздільної здатності, наприклад 320x240
            // Формат 24bpp (3 байти на піксель)
            int width = 320;
            int height = 240;

            // Якщо даних замало для картинки, виходимо
            if (data == null || data.Length < 100) return;

            try
            {
                // Створюємо Bitmap у пам'яті
                Bitmap bmp = new Bitmap(width, height, PixelFormat.Format24bppRgb);
                BitmapData bmpData = bmp.LockBits(new Rectangle(0, 0, width, height), ImageLockMode.WriteOnly, bmp.PixelFormat);

                // Копіюємо дані в текстуру бітмапа
                int bytesNeeded = bmpData.Stride * height;
                int bytesToCopy = Math.Min(bytesNeeded, data.Length);

                Marshal.Copy(data, 0, bmpData.Scan0, bytesToCopy);

                bmp.UnlockBits(bmpData);

                // Оновлюємо UI (потокобезпечно)
                if (pbNoise.InvokeRequired)
                {
                    pbNoise.BeginInvoke(new Action(() =>
                    {
                        var old = pbNoise.Image;
                        pbNoise.Image = bmp;
                        if (old != null) old.Dispose(); // Чистимо пам'ять
                    }));
                }
                else
                {
                    var old = pbNoise.Image;
                    pbNoise.Image = bmp;
                    if (old != null) old.Dispose();
                }
            }
            catch (Exception)
            {
                // Ігноруємо помилки відмальовування (не критично для криптографії)
            }
        }

        private async Task RunCryptoTask(Action action)
        {
            SetControlsState(false);
            try
            {
                // Виконуємо важку роботу у фоновому потоці
                await Task.Run(action);
            }
            catch (Exception ex)
            {
                Log($"[CRITICAL ERROR] {ex.Message}");
                MessageBox.Show(ex.Message, "Помилка криптографії", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                SetControlsState(true);
            }
        }

        private void SetControlsState(bool enabled)
        {
            btnSelectFile.Enabled = enabled;
            // Розумна активація кнопок
            bool isEncFile = selectedFilePath != null && selectedFilePath.EndsWith(".enc");
            btnEncrypt.Enabled = enabled && selectedFilePath != null && !isEncFile;
            btnDecrypt.Enabled = enabled && isEncFile;
            toolStripStatusLabel1.Text = enabled ? "Готовий" : "Виконується обробка...";
            Cursor = enabled ? Cursors.Default : Cursors.WaitCursor;
        }

        private IProgress<string> GetProgressReporter()
        {
            return new Progress<string>(msg => Log(msg));
        }

        private void Log(string message)
        {
            if (txtLog.InvokeRequired)
            {
                txtLog.Invoke(new Action(() => Log(message)));
            }
            else
            {
                txtLog.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}{Environment.NewLine}");
                toolStripStatusLabel1.Text = message;
                statusStrip1.Refresh();
            }
        }

        private void button1_Click(object sender, EventArgs e)
        {
            string infoMessage = "Програма призначена в якості демонстрації прототипу додатку для шифрування медіафайлів (медіапотоків) " +
                         "методом потокового шифрування (ChaCha20).\n\n" +
                         "Розроблено в рамках магістерської кваліфікаційної роботи.\n" +
                         "Розробник: Горохов Іван (КНмаг21), 2025 р.";
            MessageBox.Show(infoMessage, "Про програму", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
    }
}
