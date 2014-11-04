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
    public partial class FormHostEditor : Form
    {
        public FormHostEditor()
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

        public string IP
        {
            get { return this.textBoxIP.Text.Trim(); }
            set { this.textBoxIP.Text = value.Trim(); }
        }

        public string Domain
        {
            get { return this.textBoxDomain.Text.Trim(); }
            set { this.textBoxDomain.Text = value.Trim(); }
        }
    }
}
