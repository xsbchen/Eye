using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace Eye
{
    public partial class FormRuleEditor : Form
    {
        public FormRuleEditor()
        {
            InitializeComponent();

            this.AcceptButton = this.buttonOK;
            this.CancelButton = this.buttonCancel;

            this.buttonOK.DialogResult = DialogResult.OK;
            this.buttonCancel.DialogResult = DialogResult.Cancel;
        }

        private void buttonOK_Click(object sender, EventArgs e)
        {
            
        }

        private void buttonCancel_Click(object sender, EventArgs e)
        {
            
        }

        public string Match
        {
            get { return this.textBoxMatch.Text.Trim(); }
            set { this.textBoxMatch.Text = value.Trim(); }
        }

        public string Replace
        {
            get { return this.textBoxReplace.Text.Trim(); }
            set { this.textBoxReplace.Text = value.Trim(); }
        }

        private void buttonBrowse_Click(object sender, EventArgs e)
        {
            string url = "http://pay.qq.com/";

            if (this.textBoxMatch.Text.Length > 0)
            {
                url = this.textBoxMatch.Text;
            }

            Uri targetUri = new Uri(url);
            string replace = String.Empty;

            if (targetUri.AbsolutePath.EndsWith("/"))
            {
                FolderBrowserDialog fbd = new FolderBrowserDialog();
                fbd.ShowNewFolderButton = true;
                if (fbd.ShowDialog() == DialogResult.OK)
                {
                    replace = fbd.SelectedPath + "\\";
                }
            }
            else
            {
                OpenFileDialog ofd = new OpenFileDialog();
                ofd.RestoreDirectory = true;

                if (ofd.ShowDialog() == DialogResult.OK)
                {
                    replace = ofd.FileName;
                }
            }

            if (replace.Length > 0)
            {
                this.textBoxReplace.Text = replace;
            }
        }
    }
}
