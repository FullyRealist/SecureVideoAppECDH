using AxWMPLib;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Drawing;
        private string? selectedFilePath;
using System.IO;
using System.Runtime.InteropServices; // Äëÿ Marshal.Copy
using System.Threading.Tasks;
using System.Windows.Forms;

namespace SecureVideoApp
{
    public partial class MainForm : Form
    {

        // == Äàí³ ïðîãðàìè ==
        private string selectedFilePath;
        private const string KeysFile = "ECDH.key"; // Ôàéë äëÿ çáåð³ãàííÿ êëþ÷³â

        // Êëþ÷³ ïîòî÷íîãî êîðèñòóâà÷à (X25519)
        private byte[] myPrivateKey;
        private byte[] myPublicKey;

        // Åêçåìïëÿð íàøîãî êðèïòî-ðóø³ÿ
        private HybridVideoEncryptor encryptor = new HybridVideoEncryptor();

        public MainForm()
        {
            // ²í³ö³àë³çàö³ÿ êîìïîíåíò³â äèçàéíåðà (WMP ñòâîðþºòüñÿ òóò)
            InitializeComponent();

            // Çàâàíòàæåííÿ àáî ãåíåðàö³ÿ êëþ÷³â
            InitializeKeys();

            // Ïîïåðåäíº íàëàøòóâàííÿ ïëåºðà
            try
            {
                axWindowsMediaPlayer1.uiMode = "none"; // Ïðèáèðàºìî êíîïêè ïëåºðà
                axWindowsMediaPlayer1.settings.autoStart = false;
                axWindowsMediaPlayer1.settings.volume = 0; // Ùîá íå çàâàæàëî ï³ä ÷àñ òåñò³â
            }
            catch { /* ²ãíîðóºìî, ÿêùî ïëåºð ùå íå çàâàíòàæèâñÿ */ }
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

        // == Ëîã³êà ðîáîòè ç êëþ÷àìè ECDH ==
        private void InitializeKeys()
        {
            if (File.Exists(KeysFile))
            {
                try
                {
                    string[] lines = File.ReadAllLines(KeysFile);
                    myPublicKey = Convert.FromBase64String(lines[0]);
                    myPrivateKey = Convert.FromBase64String(lines[1]);
                    Log("[INFO] Ïàðà êëþ÷³â X25519 áóëà óñï³øíî çàâàíòàæåíà ç äèñêó");
                }
                catch
                {
                    Log("[WARN] Ôàéë êëþ÷³â áóëî ïîøêîäæåíî!");
                    Log("[INFO] Âèêîíóºòüñÿ ãåíåðàö³ÿ íîâî¿ ïàðè êëþ÷³â...");
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
                    bool isEncrypted = selectedFilePath.EndsWith(".enc", StringComparison.OrdinalIgnoreCase);
        }

            string outputFile = Path.ChangeExtension(selectedFilePath, null) + "_restored.mp4";
        {
            using (OpenFileDialog ofd = new OpenFileDialog())
            {
                ofd.Filter = "Ìåä³à ôàéëè|*.mp3;*.mp4;*.avi;*.mkv;*.wmv|Çàøèôðîâàí³ ìåä³à|*.enc|Óñ³ ôàéëè|*.*";
                if (ofd.ShowDialog() == DialogResult.OK)
                {
                    selectedFilePath = ofd.FileName;
                    Log($"Îáðàíî ôàéë: {Path.GetFileName(selectedFilePath)}");

                    bool isEncrypted = selectedFilePath.EndsWith(".enc");
                    btnEncrypt.Enabled = !isEncrypted;
                    btnDecrypt.Enabled = isEncrypted;

                    if (!isEncrypted)
                    {
                        // Çàâàíòàæóºìî ïðåâ'þ â³äåî
                        axWindowsMediaPlayer1.URL = selectedFilePath;
                        axWindowsMediaPlayer1.Ctlcontrols.pause(); // Ò³ëüêè ïåðøèé êàäð
                    }
                    else
                    {
                        axWindowsMediaPlayer1.Ctlcontrols.stop();
                        axWindowsMediaPlayer1.URL = "";
                        pbNoise.Image = null; // Î÷èùàºìî øóì
                    }
                }
            }
        }

        private async void BtnEncrypt_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrEmpty(selectedFilePath)) return;

            string outputFile = selectedFilePath + ".enc";
            var reporter = GetProgressReporter();

            Log("[INFO] Ïî÷àòî ïðîöåññ øèôðóâàííÿ");

            // Çàïóñêàºìî â³äåî, ùîá ïîêàçàòè "ÙÎ" ìè øèôðóºìî
            axWindowsMediaPlayer1.Ctlcontrols.play();

            await RunCryptoTask(() => encryptor.EncryptVideo(
                selectedFilePath,
                outputFile,
                myPublicKey, // Ó ðåàëüí³é ñõåì³ òóò áóâ áè Public Key îòðèìóâà÷à
                reporter,
                // Callback äëÿ â³çóàë³çàö³¿ (âèêëèêàºòüñÿ ç ãëèáèí øèôðàòîðà)
                (chunk) => UpdateNoiseVisualization(chunk)
            ));

            Log("[INFO] Ïðîöåñ øèôðóâàííÿ çàâåðøåíî");
            axWindowsMediaPlayer1.Ctlcontrols.pause();
            Log("Â³äòâîðåííÿ áóëî ïðèçóïèíåíî");
        }

        private async void BtnDecrypt_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrEmpty(selectedFilePath)) return;

            string outputFile = selectedFilePath.Replace(".enc", "_restored.mp4");
            // Çàõèñò â³ä ïåðåçàïèñó, ÿêùî ³ìåíà çá³ãàþòüñÿ
            if (outputFile == selectedFilePath) outputFile += ".restored.mp4";

            var reporter = GetProgressReporter();

            Log("[INFO] Ïî÷àòî ïðîöåññ ðîçøèôðóâàííÿ");
            // pbNoise.Image = null; // Î÷èùàºìî åêðàí øóìó

            await RunCryptoTask(() => encryptor.DecryptVideo(
                selectedFilePath,
                outputFile,
                myPrivateKey,
                reporter
            ));

            if (File.Exists(outputFile))
            {
                Log("[INFO] Çàâàíòàæåííÿ òà â³äòâîðåííÿ ðîçøèôðîâàíîãî â³äåî");
                axWindowsMediaPlayer1.URL = outputFile;
                axWindowsMediaPlayer1.Ctlcontrols.play();
                Log("[DONE] Îïåðàö³þ óñï³øíî çàâåðøåíî!");
            }
        }

        // == Äîïîì³æí³ ìåòîäè ==

        // Ìåòîä â³äìàëüîâóâàííÿ øóìó (Åíòðîï³¿)
        private void UpdateNoiseVisualization(byte[] data)
        {
            // Äëÿ â³çóàë³çàö³¿ äîñòàòíüî íåâåëèêî¿ ðîçä³ëüíî¿ çäàòíîñò³, íàïðèêëàä 320x240
            // Ôîðìàò 24bpp (3 áàéòè íà ï³êñåëü)
            int width = 320;
            int height = 240;

            // ßêùî äàíèõ çàìàëî äëÿ êàðòèíêè, âèõîäèìî
            if (data == null || data.Length < 100) return;

            try
            {
                // Ñòâîðþºìî Bitmap ó ïàì'ÿò³
                Bitmap bmp = new Bitmap(width, height, PixelFormat.Format24bppRgb);
                BitmapData bmpData = bmp.LockBits(new Rectangle(0, 0, width, height), ImageLockMode.WriteOnly, bmp.PixelFormat);

                // Êîï³þºìî äàí³ â òåêñòóðó á³òìàïà
                int bytesNeeded = bmpData.Stride * height;
                int bytesToCopy = Math.Min(bytesNeeded, data.Length);

                Marshal.Copy(data, 0, bmpData.Scan0, bytesToCopy);

                bmp.UnlockBits(bmpData);

                // Îíîâëþºìî UI (ïîòîêîáåçïå÷íî)
                if (pbNoise.InvokeRequired)
                {
                    pbNoise.BeginInvoke(new Action(() =>
                    {
                        var old = pbNoise.Image;
                        pbNoise.Image = bmp;
                        if (old != null) old.Dispose(); // ×èñòèìî ïàì'ÿòü
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
                // ²ãíîðóºìî ïîìèëêè â³äìàëüîâóâàííÿ (íå êðèòè÷íî äëÿ êðèïòîãðàô³¿)
            }
        }

        private async Task RunCryptoTask(Action action)
        {
            SetControlsState(false);
            try
            {
            bool isEncFile = selectedFilePath != null && selectedFilePath.EndsWith(".enc", StringComparison.OrdinalIgnoreCase);
                await Task.Run(action);
            }
            catch (Exception ex)
            {
                Log($"[CRITICAL ERROR] {ex.Message}");
                MessageBox.Show(ex.Message, "Ïîìèëêà êðèïòîãðàô³¿", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                SetControlsState(true);
            }
        }

        private void SetControlsState(bool enabled)
        {
            btnSelectFile.Enabled = enabled;
            // Ðîçóìíà àêòèâàö³ÿ êíîïîê
            bool isEncFile = selectedFilePath != null && selectedFilePath.EndsWith(".enc");
            btnEncrypt.Enabled = enabled && selectedFilePath != null && !isEncFile;
            btnDecrypt.Enabled = enabled && isEncFile;
            toolStripStatusLabel1.Text = enabled ? "Ãîòîâèé" : "Âèêîíóºòüñÿ îáðîáêà...";
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
            string infoMessage = "Ïðîãðàìà ïðèçíà÷åíà â ÿêîñò³ äåìîíñòðàö³¿ ïðîòîòèïó äîäàòêó äëÿ øèôðóâàííÿ ìåä³àôàéë³â (ìåä³àïîòîê³â) " +
                         "ìåòîäîì ïîòîêîâîãî øèôðóâàííÿ (ChaCha20).\n\n" +
                         "Ðîçðîáëåíî â ðàìêàõ ìàã³ñòåðñüêî¿ êâàë³ô³êàö³éíî¿ ðîáîòè.\n" +
                         "Ðîçðîáíèê: Ãîðîõîâ ²âàí (ÊÍìàã21), 2025 ð.";
            MessageBox.Show(infoMessage, "Ïðî ïðîãðàìó", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
    }
}
