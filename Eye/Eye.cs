using System;
using System.IO;
using System.Net;
using System.Xml;
using System.Text;
using System.Linq;
using System.Windows;
using System.Drawing;
using Microsoft.Win32;
using System.Windows.Forms;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using Fiddler;

[assembly: Fiddler.RequiredVersion("2.3.5.0")]

namespace Eye
{
    public class Eye : IFiddlerExtension, IAutoTamper, IMessageFilter
    {
        public Eye()
        {
            this.InitializeComponent();

            this.textBoxWatchPath.Text = this.watcher.Path = "C:\\";
            this.textBoxMatchUrl.Text = this.matchUrl = "http://pay.qq.com/";

            this.dictContentType.Add(".shtml", "text/html");
            this.dictContentType.Add(".html", "text/html");
            this.dictContentType.Add(".htm", "text/html");
            this.dictContentType.Add(".js", "application/x-javascript");
            this.dictContentType.Add(".css", "text/css");
            this.dictContentType.Add(".jpg", "image/jpeg");
            this.dictContentType.Add(".gif", "image/gif");
            this.dictContentType.Add(".png", "image/png");

            try
            {
                RegistryKey pRegKey = Registry.LocalMachine;
                pRegKey = pRegKey.OpenSubKey("SOFTWARE\\Microsoft\\Fiddler2");

                string scriptPath = pRegKey.GetValue("LMScriptPath").ToString();
                scriptPath = scriptPath.TrimStart('\"').TrimEnd('\"');
                this.xmlFilePath = Path.Combine(scriptPath, "eye\\eye.xml");
            }
            catch { }

            this.LoadDataFromXml();
            Application.AddMessageFilter(this); 
        }

        public bool PreFilterMessage(ref Message m)
        {
            Control control = Control.FromHandle(m.HWnd);
            if (m.Msg == WM_LBUTTONDBLCLK && control is ListView)
                {
                    ListView listView = (ListView)control;
                    Point point = listView.PointToClient(Control.MousePosition);
                    if (listView.GetItemAt(point.X, point.Y) == null)
                    {
                        if (listView.Name == "Rules")
                        {
                            FormRuleEditor editorForm = new FormRuleEditor();
                            if (editorForm.ShowDialog() == DialogResult.OK)
                            {
                                string match = editorForm.Match;
                                string replace = editorForm.Replace;

                                ListViewItem item = new ListViewItem(new string[] { match, replace }, 0);
                                item.Checked = true;
                                this.listViewRule.Items.Add(item);
                                this.UpdateList(listView);
                            }
                        }
                        else
                        {
                            FormHostEditor editorForm = new FormHostEditor();
                            if (editorForm.ShowDialog() == DialogResult.OK)
                            {
                                string ip = editorForm.IP;
                                string domain = editorForm.Domain;

                                ListViewItem item = new ListViewItem(new string[] { ip, domain }, 0);
                                item.Checked = true;
                                this.listViewHost.Items.Add(item);
                                this.UpdateList(listView);
                            }
                        }
                        return true;
                    }
            }
            return false;
        }

        #region IFiddlerExtension 成员
        public void OnLoad()
        {
            //this.InitializeComponent();
            FiddlerApplication.UI.lvSessions.AddBoundColumn("ReplaceHost", 4, 96, "x-replacehost");
            FiddlerApplication.UI.lvSessions.AddBoundColumn("ReplaceFiles", 6, 125, "x-replacefiles");
            FiddlerApplication.UI.tabsViews.TabPages.Add(tabPageMain);
        }

        public void OnBeforeUnload()
        {
            this.SaveSettingsToXml();
            this.tabPageMain.Dispose();
        }
        #endregion

        #region IAutoTamper 成员
        public void AutoTamperRequestBefore(Session oSession)
        {
            //this.cookie = oSession.oRequest["Cookie"];
            //FiddlerApplication.Log.LogFormat("on AutoTamperRequestBefore:{0}", oSession.url);
            if (this.bEnableRules)
            {
                if (!oSession.uriContains("/cgi-bin"))
                {
                    var result = from pair in this.dictRules orderby pair.Key select pair;
                    foreach (KeyValuePair<string, string> rulePair in result)
                    {

                        string url = oSession.fullUrl;
                        string replace = rulePair.Key;
                        //FiddlerApplication.Log.LogString(url);
                        if (url.IndexOf(replace) == 0)
                        {
                            string replaceWith = rulePair.Value;
                            string fileName = url.Replace(replace, replaceWith).Replace('/', '\\').Split('?')[0];
                            bool fileExists = true;

                            if (fileName.EndsWith("\\"))
                            {
                                fileExists = false;
                                string[] idxs = { "index.shtml", "index.html", "index.htm" };

                                foreach (string idx in idxs)
                                {
                                    string tempFileName = fileName + idx;
                                    if (File.Exists(tempFileName))
                                    {
                                        fileName = tempFileName;
                                        fileExists = true;
                                        break;
                                    }
                                }
                            }
                            else
                            {
                                fileExists = File.Exists(fileName);
                            }

                            if (fileExists)
                            {
                                string extension = Path.GetExtension(fileName);
                                string replaceFiles = "";

                                if (extension == ".shtml" || extension == ".html" || extension == ".htm")
                                {
                                    Include include = new Include(oSession.host, replaceWith, oSession.oRequest["Cookie"]);
                                    string content = include.ParseFile(fileName);
                                    if (!oSession.bHasResponse)
                                    {
                                        oSession.utilCreateResponseAndBypassServer();
                                    }
                                    oSession.utilSetResponseBody(content);
                                    oSession.oResponse["Content-Type"] = "text/html";
                                    replaceFiles = include.ReplaceFiles;
                                }
                                else
                                {
                                    oSession["x-replywithfile"] = fileName;
                                    replaceFiles = Path.GetFileName(fileName);
                                }

                                oSession["x-replacefiles"] =replaceFiles;
                                oSession["ui-backcolor"] = RuleMatchBackColor;
                            }
                        }
                    }
                }
            }

            if (this.bEnableHosts)
            {
                string overridenHost = oSession.host.ToLower();
                var result = from pair in this.dictHosts orderby pair.Key select pair;
                foreach (KeyValuePair<string, string> hostPair in result)
                {
                    //FiddlerApplication.Log.LogString("on dict:" + hostPair.Value.ToLower());
                    
                    if (hostPair.Key.ToLower() == overridenHost)
                    {
                        int port = oSession.port;
                        string host;
                        Utilities.CrackHostAndPort(hostPair.Value, out host, ref port);

                        oSession["x-overridehost"] = host + ":" + port.ToString();
                        oSession["x-replacehost"] = host;

                        if (oSession.isTunnel)
                        {
                            oSession["x-overrideCertCN"] = oSession.hostname;
                        }

                        oSession.bypassGateway = true;
                        //oSession["ui-backcolor"] = backColor;
                        //oSession["ui-bold"] = "true";
                        break;
                    }
                }
            }
            //oSession.oFlags.Add("req-cookie", this.cookie);
            //oSession.bBufferResponse = true;
        }
        public void AutoTamperRequestAfter(Session oSession) { /*FiddlerApplication.Log.LogFormat("on AutoTamperRequestAfter:{0}", oSession.url);*/ }
        public void AutoTamperResponseBefore(Session oSession) { /*FiddlerApplication.Log.LogFormat("on AutoTamperResponseBefore:{0}", oSession.url);*/ }
        public void OnBeforeReturningError(Session oSession) { /*FiddlerApplication.Log.LogFormat("on OnBeforeReturningError:{0}", oSession.url);*/ }

        public void AutoTamperResponseAfter(Session oSession)
        {
            //FiddlerApplication.Log.LogFormat("on AutoTamperResponseAfter:{0}", oSession.SuggestedFilename);
            string urlPath = oSession.url.Split('?')[0];
            string extension = Path.GetExtension(urlPath);
            if (this.bHideImages && (oSession.oResponse.headers.ExistsAndContains("Content-Type", "image/")
                                    || extension == ".jpg"
                                    || extension == ".gif"
                                    || extension == ".png"))
            {
                    oSession["ui-hide"] = "true";
                    FiddlerApplication.Log.LogString("[Eye]隐藏图片：" + oSession.fullUrl);
            }
            if (this.bHideCSSs && (oSession.oResponse["Content-Type"] == "text/css" || extension == ".css"))
            {
                FiddlerApplication.Log.LogString("[Eye]隐藏CSS：" + oSession.fullUrl);
                oSession["ui-hide"] = "true";
            }
        }
        #endregion

        // 私有方法
        private void UpdateList(ListView listView)
        {
            //FiddlerApplication.Log.LogFormat("OnUpdateList for {0} listView", listView.Name);
            Dictionary<string, string> dict = null;
            int keyIdx = 0, valueIdx = 1;

            if (listView.Name == "Rules")
            {
                dict = this.dictRules;
                this.dictRules.Clear();
                this.SaveListViewDataToXml(ItemType.Rule, listView);
            }
            else
            {
                dict = this.dictHosts;
                this.dictHosts.Clear();
                this.SaveListViewDataToXml(ItemType.Host, listView);
                keyIdx = 1;
                valueIdx = 0;
            }

            foreach(ListViewItem item in listView.Items)
            {
                if (item.Checked)
                {
                    string key = item.SubItems[keyIdx].Text;
                    string value = item.SubItems[valueIdx].Text;
                    if (dict.ContainsKey(key))
                    {
                        dict[key] = value;
                    }
                    else
                    {
                        dict.Add(key, value);
                    }
                }
            }
        }

        private void SaveListViewDataToXml(ItemType type, ListView listView)
        {
            try
            {
                XmlDocument xmlDoc = new XmlDocument();
                xmlDoc.Load(xmlFilePath);
                XmlNode rootNode = null;

                if (type == ItemType.Rule)
                {
                    rootNode = xmlDoc.SelectSingleNode("/Eye/Rules");
                    rootNode.RemoveAll();
                    foreach (ListViewItem item in listView.Items)
                    {
                        string match = item.SubItems[0].Text;
                        string replace = item.SubItems[1].Text;

                        XmlElement rule = xmlDoc.CreateElement("Rule");
                        rule.SetAttribute("Enabled", item.Checked.ToString());
                        rule.SetAttribute("Match", match);
                        rule.SetAttribute("Replace", replace);
                        rootNode.AppendChild(rule);
                    }
                }
                else
                {
                    rootNode = xmlDoc.SelectSingleNode("/Eye/Hosts");
                    rootNode.RemoveAll();
                    foreach (ListViewItem item in listView.Items)
                    {
                        string ip = item.SubItems[0].Text;
                        string domain = item.SubItems[1].Text;

                        XmlElement rule = xmlDoc.CreateElement("Host");
                        rule.SetAttribute("Enabled", item.Checked.ToString());
                        rule.SetAttribute("IP", ip);
                        rule.SetAttribute("Domain", domain);
                        rootNode.AppendChild(rule);
                    }
                }

                xmlDoc.Save(xmlFilePath);
            }
            catch (Exception ex)
            {
                FiddlerApplication.Log.LogString("[Eye]保存列表数据到配置文件失败：" + ex.Message);
            }
        }

        private void SaveCheckBoxDataToXml(CheckBox checkBox)
        {
            try
            {
                XmlDocument xmlDoc = new XmlDocument();
                xmlDoc.Load(xmlFilePath);
                XmlNode settingsNode = xmlDoc.SelectSingleNode("/Eye/Settings");
                string name = checkBox.Name;
                settingsNode.Attributes[name].Value = checkBox.Checked.ToString();
                xmlDoc.Save(xmlFilePath);
            }
            catch (Exception ex)
            {
                FiddlerApplication.Log.LogString("[Eye]保存选项到配置文件失败：" + ex.Message);
            }
        }

        private void LoadDataFromXml()
        {
            try
            {
                if (!File.Exists(xmlFilePath))
                {
                    this.CreateDefaultXml();
                }

                XmlDocument xmlDoc = new XmlDocument();
                xmlDoc.Load(xmlFilePath);
                XmlNodeList ruleNodes = xmlDoc.SelectNodes("/Eye/Rules/Rule");
                XmlNodeList hostNodes = xmlDoc.SelectNodes("/Eye/Hosts/Host");
                XmlNode settingsNode = xmlDoc.SelectSingleNode("/Eye/Settings");
                XmlNodeList settingNodes = xmlDoc.SelectNodes("/Eye/Settings/Setting");

                this.checkBoxHideCSSs.Checked = this.bHideCSSs = bool.Parse(settingsNode.Attributes["HideCSSs"].Value);
                this.checkBoxHideImages.Checked = this.bHideImages = bool.Parse(settingsNode.Attributes["HideImages"].Value);
                this.checkBoxEnableRules.Checked = this.bEnableRules = bool.Parse(settingsNode.Attributes["EnableRules"].Value);
                this.checkBoxEnableHosts.Checked = this.bEnableHosts = bool.Parse(settingsNode.Attributes["EnableHosts"].Value);
                this.checkBoxEnableWatcher.Checked = this.watcher.EnableRaisingEvents = bool.Parse(settingsNode.Attributes["EnableWatcher"].Value);

                foreach (XmlNode rule in ruleNodes)
                {
                    bool bEnabled = bool.Parse(rule.Attributes["Enabled"].Value);
                    string match = rule.Attributes["Match"].Value;
                    string replace = rule.Attributes["Replace"].Value;

                    ListViewItem item = new ListViewItem(new string[] { match, replace }, 0);
                    item.Checked = bEnabled;
                    this.listViewRule.Items.Add(item);
                }

                foreach (XmlNode host in hostNodes)
                {
                    bool bEnabled = bool.Parse(host.Attributes["Enabled"].Value);
                    string ip = host.Attributes["IP"].Value;
                    string domain = host.Attributes["Domain"].Value;

                    ListViewItem item = new ListViewItem(new string[] { ip, domain }, 0);
                    item.Checked = bEnabled;
                    this.listViewHost.Items.Add(item);
                }

                foreach (XmlNode setting in settingNodes)
                {
                    string value = setting.Attributes["Value"].Value.Trim();
                    switch (setting.Attributes["Name"].Value)
                    {
                        case "WatchPath":
                            if (value.Length > 0) this.textBoxWatchPath.Text = value;
                            break;
                        case "MatchUrl":
                            this.textBoxMatchUrl.Text = value;
                            break;
                    }
                }
            }
            catch (Exception ex)
            {
                FiddlerApplication.Log.LogString("[Eye]加载配置文件失败：" + ex.Message);
            }
        }

        private void CreateDefaultXml()
        {
            try
            {
                string xmlPath = Path.GetDirectoryName(xmlFilePath);
                if (!Directory.Exists(xmlPath))
                {
                    Directory.CreateDirectory(xmlPath);
                }

                XmlDocument xmlDoc = new XmlDocument();

                XmlDeclaration dec = xmlDoc.CreateXmlDeclaration("1.0", "UTF-8", null);
                xmlDoc.AppendChild(dec);

                XmlNode root = xmlDoc.CreateNode(XmlNodeType.Element, "Eye", String.Empty);
                xmlDoc.AppendChild(root);

                XmlElement settingsNode = xmlDoc.CreateElement("Settings");
                settingsNode.SetAttribute("HideCSSs", "True");
                settingsNode.SetAttribute("HideImages", "True");
                settingsNode.SetAttribute("EnableRules", "True");
                settingsNode.SetAttribute("EnableHosts", "True");
                settingsNode.SetAttribute("EnableWatcher", "True");

                XmlElement watchPathNode = xmlDoc.CreateElement("Setting");
                watchPathNode.SetAttribute("Name", "WatchPath");
                watchPathNode.SetAttribute("Value", "C:\\");

                XmlElement matchUrlNode = xmlDoc.CreateElement("Setting");
                matchUrlNode.SetAttribute("Name", "MatchUrl");
                matchUrlNode.SetAttribute("Value", "http://pay.qq.com/");

                settingsNode.AppendChild(watchPathNode);
                settingsNode.AppendChild(matchUrlNode);
                root.AppendChild(settingsNode);
                
                XmlNode rulesNode = xmlDoc.CreateNode(XmlNodeType.Element, "Rules", "");
                root.AppendChild(rulesNode);

                XmlNode hostsNode = xmlDoc.CreateNode(XmlNodeType.Element, "Hosts", String.Empty);
                root.AppendChild(hostsNode);

                xmlDoc.Save(xmlFilePath);
            }
            catch (Exception ex)
            {
                FiddlerApplication.Log.LogString("[Eye]创建默认配置文件失败：" + ex.Message);
            }
        }

        private void SaveSettingsToXml()
        {
            try
            {
                XmlDocument xmlDoc = new XmlDocument();
                xmlDoc.Load(xmlFilePath);
                XmlNodeList settingNodes = xmlDoc.SelectNodes("/Eye/Settings/Setting");

                foreach (XmlNode setting in settingNodes)
                {
                    string value = "";
                    switch (setting.Attributes["Name"].Value)
                    {
                        case "WatchPath":
                            value = this.watcher.Path;
                            break;
                        case "MatchUrl":
                            value = this.textBoxMatchUrl.Text.Trim();
                            break;
                    }
                    setting.Attributes["Value"].Value = value;
                }

                xmlDoc.Save(xmlFilePath);
            }
            catch (Exception ex)
            {
                FiddlerApplication.Log.LogString("[Eye]保存设置到配置文件失败：" + ex.Message);
            }
        }

        private void InitializeComponent()
        {
            this.tabPageMain = new TabPage("Eye");

            this.checkBoxHideCSSs = new CheckBox();
            this.checkBoxHideImages = new CheckBox();
            this.checkBoxEnableRules = new CheckBox();
            this.checkBoxEnableHosts = new CheckBox();
            this.checkBoxEnableWatcher = new CheckBox();

            this.textBoxWatchPath = new TextBox();
            this.buttonBrowse = new Button();
            this.textBoxMatchUrl = new TextBox();
            this.label1 = new Label();

            this.listViewRule = new ListView();
            this.listViewHost = new ListView();

            this.watcher = new FileSystemWatcher();

            // 
            // checkBoxHideCSSs
            // 
            this.checkBoxHideCSSs.AutoSize = true;
            this.checkBoxHideCSSs.Checked = true;
            this.checkBoxHideCSSs.CheckState = CheckState.Checked;
            this.checkBoxHideCSSs.Location = new System.Drawing.Point(12, 12);
            this.checkBoxHideCSSs.Name = "HideCSSs";
            this.checkBoxHideCSSs.Size = new System.Drawing.Size(102, 16);
            this.checkBoxHideCSSs.TabIndex = 0;
            this.checkBoxHideCSSs.Text = "不显示CSS请求";
            this.checkBoxHideCSSs.UseVisualStyleBackColor = true;

            this.checkBoxHideCSSs.CheckedChanged += new EventHandler(this.checkBoxHideCSSs_CheckedChanged);
            
            // 
            // checkBoxHideImages
            // 
            this.checkBoxHideImages.AutoSize = true;
            this.checkBoxHideImages.Checked = true;
            this.checkBoxHideImages.CheckState = CheckState.Checked;
            this.checkBoxHideImages.Location = new System.Drawing.Point(120, 12);
            this.checkBoxHideImages.Name = "HideImages";
            this.checkBoxHideImages.Size = new System.Drawing.Size(108, 16);
            this.checkBoxHideImages.TabIndex = 0;
            this.checkBoxHideImages.Text = "不显示图片请求";
            this.checkBoxHideImages.UseVisualStyleBackColor = true;

            this.checkBoxHideImages.CheckedChanged += new EventHandler(this.checkBoxHideImages_CheckedChanged);
            
            // 
            // checkBoxEnableMatch
            // 
            this.checkBoxEnableRules.AutoSize = true;
            this.checkBoxEnableRules.Checked = true;
            this.checkBoxEnableRules.CheckState = CheckState.Checked;
            this.checkBoxEnableRules.Location = new System.Drawing.Point(234, 12);
            this.checkBoxEnableRules.Name = "EnableRules";
            this.checkBoxEnableRules.Size = new System.Drawing.Size(72, 16);
            this.checkBoxEnableRules.TabIndex = 0;
            this.checkBoxEnableRules.Text = "启用规则";
            this.checkBoxEnableRules.UseVisualStyleBackColor = true;

            this.checkBoxEnableRules.CheckedChanged += new EventHandler(this.checkBoxEnableMatch_CheckedChanged);

            // 
            // checkBoxEnableHost
            // 
            this.checkBoxEnableHosts.AutoSize = true;
            this.checkBoxEnableHosts.Checked = true;
            this.checkBoxEnableHosts.CheckState = CheckState.Checked;
            this.checkBoxEnableHosts.Location = new System.Drawing.Point(313, 12);
            this.checkBoxEnableHosts.Name = "EnableHosts";
            this.checkBoxEnableHosts.Size = new System.Drawing.Size(72, 16);
            this.checkBoxEnableHosts.TabIndex = 0;
            this.checkBoxEnableHosts.Text = "启用HOST";
            this.checkBoxEnableHosts.UseVisualStyleBackColor = true;

            this.checkBoxEnableHosts.CheckedChanged += new EventHandler(this.checkBoxEnableHost_CheckedChanged);
                                 
            // 
            // checkBoxEnableWatcher
            // 
            this.checkBoxEnableWatcher.AutoSize = true;
            this.checkBoxEnableWatcher.Enabled = true;
            this.checkBoxEnableWatcher.Location = new System.Drawing.Point(13, 38);
            this.checkBoxEnableWatcher.Name = "EnableWatcher";
            this.checkBoxEnableWatcher.Size = new System.Drawing.Size(72, 16);
            this.checkBoxEnableWatcher.TabIndex = 2;
            this.checkBoxEnableWatcher.Text = "监视目录";
            this.checkBoxEnableWatcher.UseVisualStyleBackColor = true;

            this.checkBoxEnableWatcher.CheckedChanged += new EventHandler(this.checkBoxEnableWatcher_CheckedChanged);
            
            // 
            // textBoxWatchPath
            // 
            this.textBoxWatchPath.Location = new System.Drawing.Point(91, 37);
            this.textBoxWatchPath.Name = "textBoxWatchPath";
            this.textBoxWatchPath.Size = new System.Drawing.Size(464, 21);
            this.textBoxWatchPath.TabIndex = 1;
            this.textBoxWatchPath.Text = "C:\\";

            this.textBoxWatchPath.TextChanged += new EventHandler(this.textBoxWatchPath_TextChanged);

            // 
            // buttonBrowse
            // 
            this.buttonBrowse.Location = new System.Drawing.Point(561, 36);
            this.buttonBrowse.Name = "buttonBrowse";
            this.buttonBrowse.Size = new System.Drawing.Size(75, 23);
            this.buttonBrowse.TabIndex = 3;
            this.buttonBrowse.Text = "浏览...";
            this.buttonBrowse.UseVisualStyleBackColor = true;
            this.buttonBrowse.Click += new System.EventHandler(this.buttonBrowse_Click);
           
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(12, 64);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(77, 12);
            this.label1.TabIndex = 5;
            this.label1.Text = "自动匹配为：";

            // 
            // textBoxMatchUrl
            // 
            this.textBoxMatchUrl.Location = new System.Drawing.Point(91, 62);
            this.textBoxMatchUrl.Name = "textBoxMatchUrl";
            this.textBoxMatchUrl.Size = new System.Drawing.Size(545, 21);
            this.textBoxMatchUrl.TabIndex = 4;
            this.textBoxMatchUrl.Text = "http://pay.qq.com/";

            // 
            // listViewRule
            // 
            this.listViewRule.CheckBoxes = true;
            this.listViewRule.GridLines = true;
            this.listViewRule.FullRowSelect = true;
            this.listViewRule.Location = new Point(0, 100);
            this.listViewRule.Name = "Rules";
            this.listViewRule.Size = new Size(500, 350);
            this.listViewRule.TabIndex = 1;
            this.listViewRule.UseCompatibleStateImageBehavior = false;
            this.listViewRule.View = View.Details;

            this.listViewRule.AllowDrop = true;
            this.listViewRule.InsertionMark.Color = Color.Red;

            this.listViewRule.Columns.Add("Match", 215);
            this.listViewRule.Columns.Add("Replace", 550);

            this.listViewRule.MouseDoubleClick += new MouseEventHandler(this.listViewRule_MouseDoubleClick);
            this.listViewRule.ItemChecked += new ItemCheckedEventHandler(this.listView_ItemChecked);
            this.listViewRule.KeyDown += new KeyEventHandler(this.listView_KeyDown);

            this.listViewRule.ItemDrag += new ItemDragEventHandler(this.listView_ItemDrag);
            this.listViewRule.DragEnter += new DragEventHandler(this.listView_DragEnter);
            this.listViewRule.DragDrop += new DragEventHandler(this.listView_DragDrop);
            this.listViewRule.DragLeave += new EventHandler(this.listView_DragLeave);
            this.listViewRule.DragOver += new DragEventHandler(this.listView_DragOver);

            // 
            // listViewHost
            // 
            this.listViewHost.CheckBoxes = true;
            this.listViewHost.GridLines = true;
            this.listViewHost.FullRowSelect = true;
            this.listViewHost.Location = new Point(0, 390);
            this.listViewHost.Name = "Hosts";
            this.listViewHost.Size = new Size(500, 350);
            this.listViewHost.TabIndex = 1;
            this.listViewHost.UseCompatibleStateImageBehavior = false;
            this.listViewHost.View = View.Details;

            this.listViewHost.AllowDrop = true;
            this.listViewHost.InsertionMark.Color = Color.Red;

            this.listViewHost.Columns.Add("IP", 215);
            this.listViewHost.Columns.Add("Domain", 215);

            this.listViewHost.MouseDoubleClick += new MouseEventHandler(this.listViewHost_MouseDoubleClick);
            this.listViewHost.ItemChecked += new ItemCheckedEventHandler(this.listView_ItemChecked);
            this.listViewHost.KeyDown += new KeyEventHandler(this.listView_KeyDown);

            this.listViewHost.ItemDrag += new ItemDragEventHandler(this.listView_ItemDrag);
            this.listViewHost.DragEnter += new DragEventHandler(this.listView_DragEnter);
            this.listViewHost.DragDrop += new DragEventHandler(this.listView_DragDrop);
            this.listViewHost.DragLeave += new EventHandler(this.listView_DragLeave);
            this.listViewHost.DragOver += new DragEventHandler(this.listView_DragOver);

            // 
            // watcher
            // 
            //this.watcher.Path = this.watchPath;
            //this.watcher.EnableRaisingEvents = true;
            //watcher.IncludeSubdirectories = true;
            this.watcher.NotifyFilter = NotifyFilters.Attributes | NotifyFilters.CreationTime | NotifyFilters.DirectoryName;

            //this.watcher.Changed += new FileSystemEventHandler(this.fileSystemWatcher_Changed);
            this.watcher.Created += new FileSystemEventHandler(this.fileSystemWatcher_Changed);
            //this.watcher.Deleted += new FileSystemEventHandler(this.fileSystemWatcher_Changed);
            //this.watcher.Renamed += new RenamedEventHandler(this.fileSystemWatcher_Renamed);

            // 
            // oPage
            // 
            //this.oPage.AutoScroll = true;
            //FiddlerApplication.Log.LogString(this.tabPageMain.HorizontalScroll.Value.ToString());
            
            //this.oPage.HorizontalScroll.Visible = false;
            this.tabPageMain.Controls.AddRange(new Control[] { checkBoxHideCSSs, checkBoxHideImages, checkBoxEnableRules, checkBoxEnableHosts,
                                                               checkBoxEnableWatcher, textBoxWatchPath, buttonBrowse, label1, textBoxMatchUrl,
                                                               listViewRule, listViewHost });
            this.tabPageMain.SizeChanged += new EventHandler(this.tabPage_SizeChanged);
        }

        // 事件
        private void listView_ItemChecked(object sender, ItemCheckedEventArgs e)
        {
            this.UpdateList((ListView)sender);
            //FiddlerApplication.Log.LogString("on listViewRule_ItemCheck");
        }
        private void listViewRule_MouseDoubleClick(object sender, MouseEventArgs e)
        {
            ListView listView = (ListView)sender;
            ListViewItem selectedItem = listView.SelectedItems[0];
            string match = selectedItem.SubItems[0].Text;
            string replace = selectedItem.SubItems[1].Text;

            FormRuleEditor ruleEditor = new FormRuleEditor();
            ruleEditor.Match = match;
            ruleEditor.Replace = replace;

            if (DialogResult.OK == ruleEditor.ShowDialog())
            {
                match = ruleEditor.Match;
                replace = ruleEditor.Replace;
                selectedItem.SubItems[0].Text = match;
                selectedItem.SubItems[1].Text = replace;
            }

            selectedItem.Checked = !selectedItem.Checked;
            //FiddlerApplication.Log.LogString("listViewRule on double click");
        }
        private void listViewHost_MouseDoubleClick(object sender, MouseEventArgs e)
        {
            ListView listView = (ListView)sender;
            ListViewItem selectedItem = listView.SelectedItems[0];
            string ip = selectedItem.SubItems[0].Text;
            string domain = selectedItem.SubItems[1].Text;

            FormHostEditor ruleEditor = new FormHostEditor();
            ruleEditor.IP = ip;
            ruleEditor.Domain = domain;

            if (DialogResult.OK == ruleEditor.ShowDialog())
            {
                ip = ruleEditor.IP;
                domain = ruleEditor.Domain;
                selectedItem.SubItems[0].Text = ip;
                selectedItem.SubItems[1].Text = domain;
            }

            selectedItem.Checked = !selectedItem.Checked;
            //FiddlerApplication.Log.LogString("listViewHost on double click");
        }
        private void checkBoxEnableMatch_CheckedChanged(object sender, EventArgs e)
        {
            this.bEnableRules = this.listViewRule.Enabled = this.checkBoxEnableRules.Checked;
            this.SaveCheckBoxDataToXml((CheckBox)sender);
        }
        private void checkBoxEnableHost_CheckedChanged(object sender, EventArgs e)
        {
            this.bEnableHosts = this.listViewHost.Enabled = this.checkBoxEnableHosts.Checked;
            this.SaveCheckBoxDataToXml((CheckBox)sender);
        }
        private void checkBoxHideCSSs_CheckedChanged(object sender, EventArgs e)
        {
            this.bHideCSSs = this.checkBoxHideCSSs.Checked;
            this.SaveCheckBoxDataToXml((CheckBox)sender);
        }
        private void checkBoxHideImages_CheckedChanged(object sender, EventArgs e)
        {
            this.bHideImages = this.checkBoxHideImages.Checked;
            this.SaveCheckBoxDataToXml((CheckBox)sender);
        }
        private void checkBoxEnableWatcher_CheckedChanged(object sender, EventArgs e)
        {
            bool bChecked = this.checkBoxEnableWatcher.Checked;
            this.watcher.EnableRaisingEvents = bChecked;
            this.textBoxMatchUrl.Enabled = bChecked;
            this.textBoxWatchPath.Enabled = bChecked;
            this.buttonBrowse.Enabled = bChecked;
        }
        void textBoxWatchPath_TextChanged(object sender, EventArgs e)
        {
            string path = this.textBoxWatchPath.Text.Trim();
            if (path.Length > 0)
            {
                this.watcher.Path = path;
            }
        }
        private void buttonBrowse_Click(object sender, EventArgs e)
        {
            FolderBrowserDialog fbd = new FolderBrowserDialog();
            fbd.ShowDialog();
            this.textBoxWatchPath.Text = fbd.SelectedPath;
        }
        private void listView_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.KeyCode == Keys.Delete)
            {
                ListView listView = (ListView)sender;
                foreach (ListViewItem item in listView.SelectedItems)
                {
                    listView.Items.Remove(item);
                }
                e.Handled = true;
                this.UpdateList(listView);
            }
            else if (e.Control)
            {
                ListView listView = (ListView)sender;
                switch (e.KeyCode)
                {
                    case Keys.A: //全选
                        {
                            listView.MultiSelect = true;
                            foreach (ListViewItem item in listView.Items)
                            {
                                item.Selected = true;
                            }
                            break;
                        }
                    case Keys.C: //复制
                        {
                            var buffer = new StringBuilder();

                            foreach (var item in listView.Items.Cast<ListViewItem>().Where(item => item.Selected))
                            {
                                foreach (ListViewItem.ListViewSubItem subItem in item.SubItems)
                                {
                                    buffer.AppendFormat("{0}\t", subItem.Text.Trim());
                                }
                                //buffer.Remove(buffer.Length - 1, 1);
                                buffer.Append('|');
                            }

                            buffer.Replace("\t|", Environment.NewLine);

                            try
                            {
                                Clipboard.SetText(buffer.ToString());
                                //Clipboard.SetData(listView.Name + ".SelectedItems[]", listView.SelectedItems);
                            }
                            catch (Exception exception)
                            {
                                FiddlerApplication.Log.LogFormat("[Eye]复制到剪切板时发生错误：{0}", exception.Message);
                                Clipboard.Clear();
                            }

                            break;
                        }
                    case Keys.V: //粘贴
                        {
                            string text = Clipboard.GetText();

                            MatchCollection results = Regex.Matches(text, @"^(.+)\t(.+)" + Environment.NewLine, RegexOptions.IgnoreCase | RegexOptions.Multiline);
                            foreach (Match m in results)
                            {
                                string c1 = m.Groups[1].ToString().Trim();
                                string c2 = m.Groups[2].ToString().Trim();

                                ListViewItem item = new ListViewItem(new string[] { c1, c2 }, 0);
                                listView.Items.Add(item);
                            }
                            break;
                        }
                    case Keys.D:
                        {
                            foreach (var item in listView.Items.Cast<ListViewItem>().Where(item => item.Selected))
                            {
                                listView.Items.Add((ListViewItem)item.Clone());
                            }
                            break;
                        }
                }
            }
        }
        private void tabPage_SizeChanged(object sender, EventArgs e)
        {
            int width = this.tabPageMain.Width;
            int height = (this.tabPageMain.Height - 100) / 2;

            this.listViewRule.Width = width;
            this.listViewRule.Height = height;

            this.listViewHost.Width = width;
            this.listViewHost.Height = height;
            this.listViewHost.Location = new Point(0, height + 100);

            //FiddlerApplication.Log.LogString(this.oPage.HorizontalScroll.Value.ToString());
            //FiddlerApplication.Log.LogString("size change(" + width + "," + height + ")");
        }

        #region ListView列表项拖动
        private void listView_ItemDrag(object sender, ItemDragEventArgs e)
        {
            ((ListView)sender).DoDragDrop(e.Item, DragDropEffects.Move);
        }
        private void listView_DragEnter(object sender, DragEventArgs e)
        {
            e.Effect = e.AllowedEffect;
        }
        private void listView_DragOver(object sender, DragEventArgs e)
        {
            ListView listView = (ListView)sender;
            Point targetPoint = listView.PointToClient(new Point(e.X, e.Y));
            int targetIndex = listView.InsertionMark.NearestIndex(targetPoint);

            if (targetIndex > -1)
            {
                Rectangle itemBounds = listView.GetItemRect(targetIndex);
                if (targetPoint.X > itemBounds.Left + (itemBounds.Width / 2))
                {
                    listView.InsertionMark.AppearsAfterItem = true;
                }
                else
                {
                    listView.InsertionMark.AppearsAfterItem = false;
                }
            }
            listView.InsertionMark.Index = targetIndex;
        }
        private void listView_DragLeave(object sender, EventArgs e)
        {
            ((ListView)sender).InsertionMark.Index = -1;
        }
        private void listView_DragDrop(object sender, DragEventArgs e)
        {
            ListView listView = (ListView)sender;
            object obj = e.Data.GetData("Fiddler.Session[]");

            if (obj != null && listView.Name == "Rules")
            {
                Session session = ((Session[])(obj))[0];

                FormRuleEditor ruleEditor = new FormRuleEditor();
                ruleEditor.Match = session.fullUrl;
                if (ruleEditor.ShowDialog() == DialogResult.OK)
                {
                    string match = ruleEditor.Match;
                    string replace = ruleEditor.Replace;
                    ListViewItem item = new ListViewItem(new string[] { match, replace }, 0);
                    item.Checked = true;
                    this.listViewRule.Items.Add(item);
                }
                ((ListView)sender).InsertionMark.Index = -1;
            }
            else
            {

                int targetIndex = listView.InsertionMark.Index;
                if (targetIndex == -1)
                {
                    return;
                }

                if (listView.InsertionMark.AppearsAfterItem)
                {
                    targetIndex++;
                }

                ListViewItem draggedItme = (ListViewItem)e.Data.GetData(typeof(ListViewItem));

                listView.Items.Insert(targetIndex, (ListViewItem)draggedItme.Clone());

                if ((Control.ModifierKeys & Keys.Control) == 0)
                {
                    listView.Items.Remove(draggedItme);
                }

                this.UpdateList(listView);
            }
        }
        #endregion

        private void fileSystemWatcher_Changed(object sender, FileSystemEventArgs e)
        {
            FiddlerApplication.Log.LogFormat("[Eye]文件重命名事件处理逻辑{0}  {1}  {2}", e.ChangeType, e.FullPath, e.Name);
            if (e.ChangeType == WatcherChangeTypes.Created)
            {
                string match = this.textBoxMatchUrl.Text.Trim();
                string replace = e.FullPath + "\\";

                ListViewItem item = new ListViewItem(new string[] { match, replace }, 0);
                this.listViewRule.Items.Add(item);
            }
            //this.UpdateList(this.listViewRule);
        }
        private void fileSystemWatcher_Renamed(object sender, RenamedEventArgs e)
        {
            FiddlerApplication.Log.LogFormat("[Eye]文件重命名事件处理逻辑{0}  {1}  {2}", e.ChangeType, e.FullPath, e.Name);
        }

        // 内嵌类，用于解释html
        class Include
        {
            public Include(string host, string path, string cookie)
            {
                this.host = host;
                this.path = path;
                this.cookie = cookie;
                this.replaceFiles = new StringBuilder();
            }

            public string ParseFile(string fileName)
            {
                string html = GetLocalContent(fileName);
                this.addReplaceFiles(fileName);
                MatchEvaluator me = new MatchEvaluator(this.ReplaceInclude);
                return Regex.Replace(html, @"<!--\#include\ virtual=\""(.+)\""\s*-->", me);
            }

            public string ParseHtml(string html)
            {
                MatchEvaluator me = new MatchEvaluator(this.ReplaceInclude);
                return Regex.Replace(html, @"<!--\#include\ virtual=\""(.+)\""\s*-->", me);
            }

            public string ReplaceFiles
            {
                get { return this.replaceFiles.ToString(); }
            }

            private string GetRemoteContent(string url)
            {
                FiddlerApplication.Log.LogFormat("[Eye]尝试把请求替换为远程文件：{0}", url);

                try
                {
                    HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
                    request.Timeout = 30000;
                    request.Headers.Set("Cookie", this.cookie);
                    HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                    Stream streamReceive = response.GetResponseStream();
                    StreamReader streamReader = new StreamReader(streamReceive);
                    string strReplace = streamReader.ReadToEnd();
                    streamReader.Close();
                    streamReceive.Close();
                    return strReplace;
                }
                catch (Exception e)
                {
                    string errorMsg = "[Eye]请求远程文件时发生错误:" + e.Message;
                    FiddlerApplication.Log.LogString(errorMsg);
                    return errorMsg;
                }
            }

            private string GetLocalContent(string fileName)
            {
                FiddlerApplication.Log.LogFormat("[Eye]尝试把请求替换为本地文件：{0}", fileName);

                try
                {
                    StreamReader sFile = new StreamReader(fileName);
                    string strReplace = sFile.ReadToEnd();
                    sFile.Close();
                    return strReplace;
                }
                catch (Exception e)
                {
                    string errorMsg = "[Eye]读取文件时发生错误:" + e.Message;
                    FiddlerApplication.Log.LogString(errorMsg);
                    return errorMsg;
                }
            }

            private string ReplaceInclude(Match m)
            {
                string strFile = m.Groups[1].ToString();
                string strReplace = String.Empty;

                if (strFile.Contains("/cgi-bin/"))
                {
                    strReplace = this.GetRemoteContent("http://" + this.host + strFile);
                }
                else
                {
                    string localFile = this.path + strFile.Replace('/', '\\').Split('?')[0];
                    localFile = localFile.Replace("\\\\", "\\");
                    if (File.Exists(localFile))
                    {
                        strReplace = this.GetLocalContent(localFile);
                        this.addReplaceFiles(localFile);
                    }
                    else
                    {
                        strReplace = this.GetRemoteContent("http://" + this.host + strFile);
                    }
                }

                strReplace = ParseHtml(strReplace);

                return strReplace;
            }

            private void addReplaceFiles(string fileFullName)
            {
                string fileName = Path.GetFileName(fileFullName);

                if (this.replaceFiles.Length <= 0)
                {
                    this.replaceFiles.Append(fileName);
                }
                else
                {
                    this.replaceFiles.AppendFormat(",{0}", fileName);
                }
            }

            private string host;
            private string path;
            private string cookie;
            private StringBuilder replaceFiles;
        }
        
        // 控件
        private TabPage tabPageMain;
        private CheckBox checkBoxHideCSSs;
        private CheckBox checkBoxHideImages;
        private CheckBox checkBoxEnableRules;
        private CheckBox checkBoxEnableHosts;
        private TextBox textBoxWatchPath;
        private CheckBox checkBoxEnableWatcher;
        private Button buttonBrowse;
        private TextBox textBoxMatchUrl;
        private Label label1;
        private ListView listViewRule;
        private ListView listViewHost;

        // 变量
        //private string cookie = String.Empty;
        //private string host = String.Empty;
        //private string path = String.Empty;
        private bool bEnableHosts = true;
        private bool bEnableRules = true;
        private bool bHideCSSs = true;
        private bool bHideImages = true;
        private Dictionary<string, string> dictRules = new Dictionary<string,string>();
        private Dictionary<string, string> dictHosts = new Dictionary<string, string>();
        private Dictionary<string, string> dictContentType = new Dictionary<string, string>();
        private enum ItemType { Rule, Host };
        private FileSystemWatcher watcher;
        private string watchPath = String.Empty;
        private string matchUrl = String.Empty;
        private string xmlFilePath = "C:\\Program Files\\Fiddler2\\Scripts\\eye\\eye.xml";

        // 常量
        private const string RuleMatchBackColor = "PapayaWhip";
        private const int WM_LBUTTONDBLCLK = 0x0203;
    }
}
