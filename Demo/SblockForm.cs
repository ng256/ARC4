using System;
using System.ComponentModel;
using System.Drawing;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

namespace ARC4Demo
{
    public class SblockForm : Form
    {
        private TextBox txtSBlock;
        private HScrollBar scrolIV;
        private Button cmdOK;
        private Button cmdCancel;
        private Timer timer;
        private TextBox txtPassword;
        private CheckBox chkPassword;
        private Button cmdReset;
        private IContainer components;
        private byte[] sblock;

        public ARC4SBlock SBlock
        {
            get
            {
                return (ARC4SBlock)sblock;
            }
        }

        public string Password
        {
            get
            {
                return txtPassword.Text;
            }
            set
            {
                txtPassword.Text = value;
            }
        }

        public SblockForm()
        {
            InitializeComponent();
        }

        public SblockForm(ARC4SBlock s)
            : this()
        {
            sblock = s;
        }

        private void InitializeComponent()
        {
            components = new System.ComponentModel.Container();
            timer = new System.Windows.Forms.Timer(components);
            txtSBlock = new System.Windows.Forms.TextBox();
            scrolIV = new System.Windows.Forms.HScrollBar();
            cmdOK = new System.Windows.Forms.Button();
            cmdCancel = new System.Windows.Forms.Button();
            txtPassword = new System.Windows.Forms.TextBox();
            chkPassword = new System.Windows.Forms.CheckBox();
            cmdReset = new System.Windows.Forms.Button();
            SuspendLayout();
            txtSBlock.Anchor = System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right;
            txtSBlock.Font = new System.Drawing.Font("Consolas", 9.75f, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, 204);
            txtSBlock.Location = new System.Drawing.Point(4, 3);
            txtSBlock.Multiline = true;
            txtSBlock.Name = "txtSBlock";
            txtSBlock.ReadOnly = true;
            txtSBlock.Size = new System.Drawing.Size(348, 274);
            txtSBlock.TabIndex = 100;
            txtSBlock.TabStop = false;
            scrolIV.Anchor = System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right;
            scrolIV.LargeChange = 65536;
            scrolIV.Location = new System.Drawing.Point(9, 280);
            scrolIV.Maximum = 2147483645;
            scrolIV.Name = "scrolIV";
            scrolIV.Size = new System.Drawing.Size(338, 18);
            scrolIV.TabIndex = 1;
            scrolIV.Value = 100;
            scrolIV.Scroll += new System.Windows.Forms.ScrollEventHandler(scrolIV_Scroll);
            cmdOK.Anchor = System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right;
            cmdOK.Location = new System.Drawing.Point(267, 327);
            cmdOK.Name = "cmdOK";
            cmdOK.Size = new System.Drawing.Size(75, 23);
            cmdOK.TabIndex = 101;
            cmdOK.Text = "&OK";
            cmdOK.UseVisualStyleBackColor = true;
            cmdOK.Click += new System.EventHandler(cmdOK_Click);
            cmdCancel.Anchor = System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right;
            cmdCancel.Location = new System.Drawing.Point(186, 327);
            cmdCancel.Name = "cmdCancel";
            cmdCancel.Size = new System.Drawing.Size(75, 23);
            cmdCancel.TabIndex = 100;
            cmdCancel.Text = "&Cancel";
            cmdCancel.UseVisualStyleBackColor = true;
            cmdCancel.Click += new System.EventHandler(cmdCancel_Click);
            txtPassword.Anchor = System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right;
            txtPassword.Location = new System.Drawing.Point(101, 301);
            txtPassword.Name = "txtPassword";
            txtPassword.Size = new System.Drawing.Size(241, 20);
            txtPassword.TabIndex = 2;
            txtPassword.TextChanged += new System.EventHandler(txtPassword_Changed);
            txtPassword.LostFocus += new System.EventHandler(OnLostFocus);
            chkPassword.Anchor = System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left;
            chkPassword.AutoSize = true;
            chkPassword.Location = new System.Drawing.Point(4, 304);
            chkPassword.Name = "chkPassword";
            chkPassword.Size = new System.Drawing.Size(91, 17);
            chkPassword.TabIndex = 1;
            chkPassword.Text = "Preview KSA:";
            chkPassword.UseVisualStyleBackColor = true;
            chkPassword.CheckedChanged += new System.EventHandler(txtPassword_Changed);
            cmdReset.Anchor = System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left;
            cmdReset.Location = new System.Drawing.Point(4, 327);
            cmdReset.Name = "cmdReset";
            cmdReset.Size = new System.Drawing.Size(75, 23);
            cmdReset.TabIndex = 0;
            cmdReset.Text = "&Reset";
            cmdReset.UseVisualStyleBackColor = true;
            cmdReset.Click += new System.EventHandler(cmdReset_Click);
            base.ClientSize = new System.Drawing.Size(354, 362);
            base.Controls.Add(cmdReset);
            base.Controls.Add(chkPassword);
            base.Controls.Add(txtPassword);
            base.Controls.Add(cmdCancel);
            base.Controls.Add(cmdOK);
            base.Controls.Add(scrolIV);
            base.Controls.Add(txtSBlock);
            base.MaximizeBox = false;
            base.MinimizeBox = false;
            MinimumSize = new System.Drawing.Size(370, 400);
            base.Name = "SblockForm";
            base.ShowIcon = false;
            base.ShowInTaskbar = false;
            base.StartPosition = System.Windows.Forms.FormStartPosition.CenterParent;
            Text = "S-Block Generator";
            base.Load += new System.EventHandler(SblockForm_Load);
            ResumeLayout(false);
            PerformLayout();
        }

        private void GenerateSBlock()
        {
            SuspendLayout();
            txtSBlock.SuspendLayout();
            txtSBlock.Clear();
            try
            {
                uint i = BitConverter.ToUInt32(BitConverter.GetBytes(scrolIV.Value), 0);
                i ^= (i >> 16);
                i *= 0x85ebca6b; // Мультипликатор из MurmurHash, усиливает разброс
                i ^= (i >> 13);
                i *= 0xc2b2ae35; // Еще один мультипликатор
                i ^= (i >> 16);

                byte[] bytes = BitConverter.GetBytes(scrolIV.Value);
                sblock = ARC4SBlock.FromSalt(bytes);
                if (chkPassword.Checked)
                {
                    using (ARC4DeriveBytes aRC4DeriveBytes = new ARC4DeriveBytes(Encoding.UTF8.GetBytes(txtPassword.Text), bytes))
                    {
                        txtSBlock.Text = Program.ToHex(aRC4DeriveBytes.State);
                    }
                }
                else
                {
                    txtSBlock.Text = sblock.ToHex();
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Hand);
            }
            ResumeLayout();
            txtSBlock.ResumeLayout();
        }

        private void TimerOnTick(object sender, EventArgs e)
        {
            GenerateSBlock();
            timer.Stop();
        }

        private void txtPassword_Changed(object sender, EventArgs e)
        {
            if (chkPassword.Checked && txtPassword.TextLength > 0)
            {
                timer.Start();
            }
        }

        private void scrolIV_Scroll(object sender, ScrollEventArgs e)
        {
            timer.Start();
        }

        private void cmdOK_Click(object sender, EventArgs e)
        {
            base.DialogResult = DialogResult.OK;
            Close();
        }

        private void cmdCancel_Click(object sender, EventArgs e)
        {
            base.DialogResult = DialogResult.Cancel;
            Close();
        }

        private void OnLostFocus(object sender, EventArgs e)
        {
            if (txtPassword.TextLength <= 0)
            {
                txtPassword.Undo();
                txtPassword.Select();
            }
        }

        private void cmdReset_Click(object sender, EventArgs e)
        {
            scrolIV.Value = scrolIV.Minimum;
            chkPassword.Checked = false;
            timer.Stop();
            sblock = ARC4SBlock.DefaultSBlock;
            txtSBlock.Text = sblock.ToHex();
        }

        private void SblockForm_Load(object sender, EventArgs e)
        {
            timer.Enabled = false;
            timer.Interval = 100;
            timer.Tick += TimerOnTick;
            txtSBlock.Text = sblock.ToHex();
        }
    }
}
