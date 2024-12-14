using System;
using System.ComponentModel;
using System.IO;
using System.Media;
using System.Security.Cryptography;
using System.Windows.Forms;

namespace ARC4Demo
{
    public class MainForm : Form
    {
        private Label lblOriginal;
        private Label lblEncrypted;
        private Label lblKey;
        private TextBox txtOriginal;
        private TextBox txtEncrypted;
        private TextBox txtPassword;
        private Button cmdEncrypt;
        private Button cmdDecrypt;
        private SplitContainer splitContainer;
        private Button cmdSBlock;
        private Container components;
        private byte[] iv = new byte[4];
        private int skip = 0;
        private bool plus = false;

        public MainForm()
        {
            InitializeComponent();
        }

        private void InitializeComponent()
        {
            txtOriginal = new System.Windows.Forms.TextBox();
            txtEncrypted = new System.Windows.Forms.TextBox();
            cmdEncrypt = new System.Windows.Forms.Button();
            cmdDecrypt = new System.Windows.Forms.Button();
            lblOriginal = new System.Windows.Forms.Label();
            lblEncrypted = new System.Windows.Forms.Label();
            lblKey = new System.Windows.Forms.Label();
            txtPassword = new System.Windows.Forms.TextBox();
            splitContainer = new System.Windows.Forms.SplitContainer();
            cmdSBlock = new System.Windows.Forms.Button();
            ((System.ComponentModel.ISupportInitialize)splitContainer).BeginInit();
            splitContainer.Panel1.SuspendLayout();
            splitContainer.Panel2.SuspendLayout();
            splitContainer.SuspendLayout();
            SuspendLayout();
            txtOriginal.Anchor = System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right;
            txtOriginal.Font = new System.Drawing.Font("Consolas", 8.25f, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, 204);
            txtOriginal.Location = new System.Drawing.Point(3, 35);
            txtOriginal.Multiline = true;
            txtOriginal.Name = "txtOriginal";
            txtOriginal.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            txtOriginal.Size = new System.Drawing.Size(313, 274);
            txtOriginal.TabIndex = 4;
            txtOriginal.TextChanged += new System.EventHandler(txtOriginal_TextChanged);
            txtEncrypted.Anchor = System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right;
            txtEncrypted.Font = new System.Drawing.Font("Consolas", 8.25f, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, 204);
            txtEncrypted.Location = new System.Drawing.Point(3, 35);
            txtEncrypted.Multiline = true;
            txtEncrypted.Name = "txtEncrypted";
            txtEncrypted.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            txtEncrypted.Size = new System.Drawing.Size(331, 274);
            txtEncrypted.TabIndex = 5;
            txtEncrypted.TextChanged += new System.EventHandler(txtEncrypted_TextChanged);
            cmdEncrypt.Anchor = System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right;
            cmdEncrypt.Enabled = false;
            cmdEncrypt.Location = new System.Drawing.Point(227, 3);
            cmdEncrypt.Name = "cmdEncrypt";
            cmdEncrypt.Size = new System.Drawing.Size(89, 26);
            cmdEncrypt.TabIndex = 2;
            cmdEncrypt.Text = "Encrypt →";
            cmdEncrypt.Click += new System.EventHandler(cmdEncrypt_Click);
            cmdDecrypt.Anchor = System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right;
            cmdDecrypt.Enabled = false;
            cmdDecrypt.Location = new System.Drawing.Point(245, 3);
            cmdDecrypt.Name = "cmdDecrypt";
            cmdDecrypt.Size = new System.Drawing.Size(89, 25);
            cmdDecrypt.TabIndex = 3;
            cmdDecrypt.Text = "← Decrypt";
            cmdDecrypt.Click += new System.EventHandler(cmdDecrypt_Click);
            lblOriginal.Location = new System.Drawing.Point(3, 10);
            lblOriginal.Name = "lblOriginal";
            lblOriginal.Size = new System.Drawing.Size(88, 18);
            lblOriginal.TabIndex = 100;
            lblOriginal.Text = "Original Text:";
            lblEncrypted.Location = new System.Drawing.Point(3, 10);
            lblEncrypted.Name = "lblEncrypted";
            lblEncrypted.Size = new System.Drawing.Size(222, 18);
            lblEncrypted.TabIndex = 101;
            lblEncrypted.Text = "Encrypted Text (HEX Encoded):";
            lblKey.Location = new System.Drawing.Point(12, 15);
            lblKey.Name = "lblKey";
            lblKey.Size = new System.Drawing.Size(91, 17);
            lblKey.TabIndex = 99;
            lblKey.Text = "Password:";
            txtPassword.Anchor = System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right;
            txtPassword.Location = new System.Drawing.Point(117, 12);
            txtPassword.Name = "txtPassword";
            txtPassword.Size = new System.Drawing.Size(457, 20);
            txtPassword.TabIndex = 0;
            txtPassword.LostFocus += new System.EventHandler(txtEncryption_LostFocus);
            splitContainer.Anchor = System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right;
            splitContainer.Location = new System.Drawing.Point(12, 38);
            splitContainer.Name = "splitContainer";
            splitContainer.Panel1.Controls.Add(txtOriginal);
            splitContainer.Panel1.Controls.Add(lblOriginal);
            splitContainer.Panel1.Controls.Add(cmdEncrypt);
            splitContainer.Panel2.Controls.Add(txtEncrypted);
            splitContainer.Panel2.Controls.Add(lblEncrypted);
            splitContainer.Panel2.Controls.Add(cmdDecrypt);
            splitContainer.Size = new System.Drawing.Size(660, 312);
            splitContainer.SplitterDistance = 319;
            splitContainer.TabIndex = 5;
            splitContainer.TabStop = false;
            cmdSBlock.Anchor = System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right;
            cmdSBlock.Location = new System.Drawing.Point(580, 12);
            cmdSBlock.Name = "cmdSBlock";
            cmdSBlock.Size = new System.Drawing.Size(89, 23);
            cmdSBlock.TabIndex = 1;
            cmdSBlock.Text = "S-Block...";
            cmdSBlock.Click += new System.EventHandler(btnSBlock_Click);
            AutoScaleBaseSize = new System.Drawing.Size(5, 13);
            base.ClientSize = new System.Drawing.Size(684, 362);
            base.Controls.Add(cmdSBlock);
            base.Controls.Add(splitContainer);
            base.Controls.Add(txtPassword);
            base.Controls.Add(lblKey);
            base.MaximizeBox = false;
            base.MinimizeBox = false;
            MinimumSize = new System.Drawing.Size(700, 400);
            base.Name = "MainForm";
            base.ShowIcon = false;
            base.ShowInTaskbar = false;
            Text = "ARC4 Demo Application";
            base.Load += new System.EventHandler(MainForm_Load);
            splitContainer.Panel1.ResumeLayout(false);
            splitContainer.Panel1.PerformLayout();
            splitContainer.Panel2.ResumeLayout(false);
            splitContainer.Panel2.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)splitContainer).EndInit();
            splitContainer.ResumeLayout(false);
            ResumeLayout(false);
            PerformLayout();
        }

        private void DoEncrypt()
        {
            if (txtPassword.TextLength == 0)
            {
                return;
            }
            try
            {
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (ARC4Stream stream = new ARC4Stream(memoryStream, txtPassword.Text, iv, leaveOpen: true))
                    {
                        using (StreamWriter streamWriter = new StreamWriter(stream))
                        {
                            streamWriter.Write(txtOriginal.Text);
                        }
                    }
                    memoryStream.Seek(0L, SeekOrigin.Begin);
                    txtEncrypted.Text = memoryStream.ToArray().ToHex();
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Hand);
            }
        }

        private void DoDecrypt()
        {
            if (txtPassword.TextLength == 0)
            {
                return;
            }
            try
            {
                using (MemoryStream stream = new MemoryStream(txtEncrypted.Text.FromHex()))
                {
                    using (ARC4Stream stream2 = new ARC4Stream(stream, txtPassword.Text, iv, skip, plus, true))
                    {
                        using (StreamReader streamReader = new StreamReader(stream2))
                        {
                            txtOriginal.Text = streamReader.ReadToEnd();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Hand);
            }
        }

        private void txtEncryption_LostFocus(object sender, EventArgs e)
        {
            if (txtPassword.TextLength <= 0)
            {
                txtPassword.Select();
                SystemSounds.Beep.Play();
            }
        }

        private void txtOriginal_TextChanged(object sender, EventArgs e)
        {
            cmdEncrypt.Enabled = txtOriginal.TextLength > 0;
        }

        private void txtEncrypted_TextChanged(object sender, EventArgs e)
        {
            cmdDecrypt.Enabled = txtEncrypted.TextLength > 0;
        }

        private void cmdEncrypt_Click(object sender, EventArgs e)
        {
            DoEncrypt();
        }

        private void cmdDecrypt_Click(object sender, EventArgs e)
        {
            DoDecrypt();
        }

        private void MainForm_Load(object sender, EventArgs e)
        {
            iv = BitConverter.GetBytes(0);
            txtPassword.Text = "fourwordsalluppercase";
            txtOriginal.Text = "Hello, world!";
            DoEncrypt();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                Container container = components;
                container?.Dispose();
            }
            base.Dispose(disposing);
        }

        private void btnSBlock_Click(object sender, EventArgs e)
        {
            using (SblockForm sblockForm = new SblockForm(iv))
            {
                sblockForm.Password = txtPassword.Text;
                if (sblockForm.ShowDialog() == DialogResult.OK)
                {
                    iv = sblockForm.IV;
                    skip = sblockForm.SkipSize;
                    plus = sblockForm.Plus;
                    txtPassword.Text = sblockForm.Password;
                }
            }
        }
    }
}
