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
        private TrackBar trackSkipSize;
        private Label lblSkipSize;
        private Label lblSeed;
        private byte[] iv;
        private int skip = 0;
        private CheckBox chkPlus;
        private CheckBox chkDual;
        private bool plus = false;
        private bool dual = false;

        public byte[] IV => iv;

        public string Password
        {
            get => txtPassword.Text;
            set => txtPassword.Text = value;
        }

        public int SkipSize
        {
            get => skip;
            set => skip = value;
        }

        public bool Plus
        {
            get => plus;
            set => plus = value;
        }

        public SblockForm()
        {
            InitializeComponent();
        }

        public SblockForm(byte[] s)
            : this()
        {
            iv = s;
        }

        private void InitializeComponent()
        {
            this.components = new System.ComponentModel.Container();
            this.timer = new System.Windows.Forms.Timer(this.components);
            this.txtSBlock = new System.Windows.Forms.TextBox();
            this.scrolIV = new System.Windows.Forms.HScrollBar();
            this.cmdOK = new System.Windows.Forms.Button();
            this.cmdCancel = new System.Windows.Forms.Button();
            this.txtPassword = new System.Windows.Forms.TextBox();
            this.chkPassword = new System.Windows.Forms.CheckBox();
            this.cmdReset = new System.Windows.Forms.Button();
            this.trackSkipSize = new System.Windows.Forms.TrackBar();
            this.lblSkipSize = new System.Windows.Forms.Label();
            this.lblSeed = new System.Windows.Forms.Label();
            this.chkPlus = new System.Windows.Forms.CheckBox();
            this.chkDual = new System.Windows.Forms.CheckBox();
            ((System.ComponentModel.ISupportInitialize)(this.trackSkipSize)).BeginInit();
            this.SuspendLayout();
            // 
            // txtSBlock
            // 
            this.txtSBlock.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.txtSBlock.Font = new System.Drawing.Font("Consolas", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.txtSBlock.Location = new System.Drawing.Point(4, 3);
            this.txtSBlock.Multiline = true;
            this.txtSBlock.Name = "txtSBlock";
            this.txtSBlock.ReadOnly = true;
            this.txtSBlock.Size = new System.Drawing.Size(348, 282);
            this.txtSBlock.TabIndex = 0;
            this.txtSBlock.TabStop = false;
            // 
            // scrolIV
            // 
            this.scrolIV.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.scrolIV.LargeChange = 65536;
            this.scrolIV.Location = new System.Drawing.Point(4, 377);
            this.scrolIV.Maximum = 2147483645;
            this.scrolIV.Name = "scrolIV";
            this.scrolIV.Size = new System.Drawing.Size(338, 20);
            this.scrolIV.TabIndex = 4;
            this.scrolIV.Value = 100;
            this.scrolIV.Scroll += new System.Windows.Forms.ScrollEventHandler(this.ScrolIV_Scroll);
            // 
            // cmdOK
            // 
            this.cmdOK.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.cmdOK.Location = new System.Drawing.Point(267, 426);
            this.cmdOK.Name = "cmdOK";
            this.cmdOK.Size = new System.Drawing.Size(75, 23);
            this.cmdOK.TabIndex = 101;
            this.cmdOK.Text = "&OK";
            this.cmdOK.UseVisualStyleBackColor = true;
            this.cmdOK.Click += new System.EventHandler(this.CmdOK_Click);
            // 
            // cmdCancel
            // 
            this.cmdCancel.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.cmdCancel.Location = new System.Drawing.Point(186, 426);
            this.cmdCancel.Name = "cmdCancel";
            this.cmdCancel.Size = new System.Drawing.Size(75, 23);
            this.cmdCancel.TabIndex = 100;
            this.cmdCancel.Text = "&Cancel";
            this.cmdCancel.UseVisualStyleBackColor = true;
            this.cmdCancel.Click += new System.EventHandler(this.CmdCancel_Click);
            // 
            // txtPassword
            // 
            this.txtPassword.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.txtPassword.Location = new System.Drawing.Point(101, 400);
            this.txtPassword.Name = "txtPassword";
            this.txtPassword.Size = new System.Drawing.Size(241, 20);
            this.txtPassword.TabIndex = 6;
            this.txtPassword.TextChanged += new System.EventHandler(this.TxtPassword_Changed);
            this.txtPassword.LostFocus += new System.EventHandler(this.TxtPassword_LostFocus);
            // 
            // chkPassword
            // 
            this.chkPassword.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left)));
            this.chkPassword.AutoSize = true;
            this.chkPassword.Location = new System.Drawing.Point(4, 403);
            this.chkPassword.Name = "chkPassword";
            this.chkPassword.Size = new System.Drawing.Size(91, 17);
            this.chkPassword.TabIndex = 5;
            this.chkPassword.Text = "Preview KSA:";
            this.chkPassword.UseVisualStyleBackColor = true;
            this.chkPassword.CheckedChanged += new System.EventHandler(this.ChkPassword_Changed);
            // 
            // cmdReset
            // 
            this.cmdReset.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left)));
            this.cmdReset.Location = new System.Drawing.Point(4, 426);
            this.cmdReset.Name = "cmdReset";
            this.cmdReset.Size = new System.Drawing.Size(75, 23);
            this.cmdReset.TabIndex = 99;
            this.cmdReset.Text = "&Reset";
            this.cmdReset.UseVisualStyleBackColor = true;
            this.cmdReset.Click += new System.EventHandler(this.CmdReset_Click);
            // 
            // trackSkipSize
            // 
            this.trackSkipSize.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.trackSkipSize.LargeChange = 256;
            this.trackSkipSize.Location = new System.Drawing.Point(4, 304);
            this.trackSkipSize.Maximum = 1024;
            this.trackSkipSize.Name = "trackSkipSize";
            this.trackSkipSize.Size = new System.Drawing.Size(338, 45);
            this.trackSkipSize.SmallChange = 256;
            this.trackSkipSize.TabIndex = 1;
            this.trackSkipSize.TickFrequency = 256;
            this.trackSkipSize.TickStyle = System.Windows.Forms.TickStyle.Both;
            this.trackSkipSize.ValueChanged += new System.EventHandler(this.TrackSkipSize_ValueChanged);
            // 
            // lblSkipSize
            // 
            this.lblSkipSize.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left)));
            this.lblSkipSize.AutoSize = true;
            this.lblSkipSize.Location = new System.Drawing.Point(1, 288);
            this.lblSkipSize.Name = "lblSkipSize";
            this.lblSkipSize.Size = new System.Drawing.Size(80, 13);
            this.lblSkipSize.TabIndex = 0;
            this.lblSkipSize.Text = "Drop down size";
            // 
            // lblSeed
            // 
            this.lblSeed.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left)));
            this.lblSeed.AutoSize = true;
            this.lblSeed.Location = new System.Drawing.Point(1, 352);
            this.lblSeed.Name = "lblSeed";
            this.lblSeed.Size = new System.Drawing.Size(94, 13);
            this.lblSeed.TabIndex = 102;
            this.lblSeed.Text = "Initialization vector";
            // 
            // chkPlus
            // 
            this.chkPlus.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left)));
            this.chkPlus.AutoSize = true;
            this.chkPlus.Location = new System.Drawing.Point(289, 348);
            this.chkPlus.Name = "chkPlus";
            this.chkPlus.Size = new System.Drawing.Size(53, 17);
            this.chkPlus.TabIndex = 3;
            this.chkPlus.Text = "RC4+";
            this.chkPlus.UseVisualStyleBackColor = true;
            this.chkPlus.CheckedChanged += new System.EventHandler(this.chkPlus_CheckedChanged);
            // 
            // chkDual
            // 
            this.chkDual.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left)));
            this.chkDual.AutoSize = true;
            this.chkDual.Location = new System.Drawing.Point(229, 348);
            this.chkDual.Name = "chkDual";
            this.chkDual.Size = new System.Drawing.Size(54, 17);
            this.chkDual.TabIndex = 2;
            this.chkDual.Text = "RC4A";
            this.chkDual.UseVisualStyleBackColor = true;
            this.chkDual.CheckedChanged += new System.EventHandler(this.chkDual_CheckedChanged);
            // 
            // SblockForm
            // 
            this.ClientSize = new System.Drawing.Size(354, 461);
            this.Controls.Add(this.chkDual);
            this.Controls.Add(this.chkPlus);
            this.Controls.Add(this.lblSeed);
            this.Controls.Add(this.lblSkipSize);
            this.Controls.Add(this.trackSkipSize);
            this.Controls.Add(this.cmdReset);
            this.Controls.Add(this.chkPassword);
            this.Controls.Add(this.txtPassword);
            this.Controls.Add(this.cmdCancel);
            this.Controls.Add(this.cmdOK);
            this.Controls.Add(this.scrolIV);
            this.Controls.Add(this.txtSBlock);
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.MinimumSize = new System.Drawing.Size(370, 500);
            this.Name = "SblockForm";
            this.ShowIcon = false;
            this.ShowInTaskbar = false;
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterParent;
            this.Text = "S-Block Generator";
            this.Load += new System.EventHandler(this.SblockForm_Load);
            ((System.ComponentModel.ISupportInitialize)(this.trackSkipSize)).EndInit();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        private void GenerateSBlock()
        {
            SuspendLayout();
            txtSBlock.SuspendLayout();
            txtSBlock.Clear();
            try
            {
                uint i = BitConverter.ToUInt32(BitConverter.GetBytes(scrolIV.Value), 0);
                
                if (dual)
                {


                    //this.MinimumSize = new Size(370 * 2 - 20, 500);
                    //this.Size = new Size(370 * 2, 500);
                    uint j = i;
                    j ^= (j >> 16);
                    j *= 0x85ebca6b;
                    j ^= (j >> 13);
                    j *= 0xc2b2ae35;
                    j ^= (j >> 16);
                    ulong k = i | (ulong)j << 32;

                    iv = BitConverter.GetBytes(k);
                }
                else
                {
                    //this.MinimumSize = new Size(370, 500);
                    //this.Size = new Size(370, 500);
                    iv = BitConverter.GetBytes(i);
                }

                byte[] key = chkPassword.Checked ? Encoding.UTF8.GetBytes(txtPassword.Text) : new byte[0];

                using (CryptoProvider arc4 = CryptoProvider.Create(key, iv, skip, plus))
                {
                    txtSBlock.Text = arc4.ToString();
                }

                using (var g = this.CreateGraphics())
                {
                    SizeF textSize = g.MeasureString(txtSBlock.Text, this.txtSBlock.Font);
                    Size size = new Size((int)textSize.Width + 20, 500);
                    this.MinimumSize = size;
                    this.Size = size;
                }

                /*using (ARC4DeriveBytes deriveBytes = new ARC4DeriveBytes(key, iv))
                {
                    txtSBlock.Text = deriveBytes.State;
                }*/
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Hand);
            }
            txtSBlock.ResumeLayout();
            ResumeLayout();
        }

        private void TrackSkipSize_ValueChanged(object sender, EventArgs e)
        {
            trackSkipSize.Value = (trackSkipSize.Value / 256) * 256;
            lblSkipSize.Text = $"Drop down size: {trackSkipSize.Value} bytes";
            skip = trackSkipSize.Value;
            timer.Start();
        }

        private void Timer_Tick(object sender, EventArgs e)
        {
            GenerateSBlock();
            timer.Stop();
        }

        private void TxtPassword_Changed(object sender, EventArgs e)
        {
            if (chkPassword.Checked && txtPassword.TextLength > 0)
            {
                timer.Start();
            }
        }
        private void TxtPassword_LostFocus(object sender, EventArgs e)
        {
            if (txtPassword.TextLength <= 0)
            {
                txtPassword.Undo();
                txtPassword.Select();
            }
        }

        private void ScrolIV_Scroll(object sender, ScrollEventArgs e)
        {
            timer.Start();
        }

        private void CmdOK_Click(object sender, EventArgs e)
        {
            base.DialogResult = DialogResult.OK;
            Close();
        }

        private void CmdCancel_Click(object sender, EventArgs e)
        {
            base.DialogResult = DialogResult.Cancel;
            Close();
        }

        private void CmdReset_Click(object sender, EventArgs e)
        {
            scrolIV.Value = scrolIV.Minimum;
            chkPassword.Checked = false;
            timer.Stop();

            GenerateSBlock();
        }

        private void SblockForm_Load(object sender, EventArgs e)
        {
            timer.Enabled = false;
            timer.Interval = 100;
            timer.Tick += Timer_Tick;

            GenerateSBlock();
        }

        private void chkDual_CheckedChanged(object sender, EventArgs e)
        {
            dual = chkDual.Checked;
            timer.Start();
        }

        private void chkPlus_CheckedChanged(object sender, EventArgs e)
        {
            plus = chkPlus.Checked;
            timer.Start();
        }

        private void ChkPassword_Changed(object sender, EventArgs e)
        {
            timer.Start();
        }
    }
}
