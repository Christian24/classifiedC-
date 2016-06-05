using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace classifiedClient
{
	/// <summary>
	/// Interaction logic for Chat.xaml
	/// </summary>
	public partial class Chat : Window
	{
		ServerConnector connector = ServerConnector.Instance;
		string publicKey;
		public Chat()
		{
			InitializeComponent();
		}
		public void SetUserName(string name)
		{
			userName.Text = name;
		}
		public void SetPublicKey(string key)
		{
			publicKey = key;
		}
	}
}
