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
	/// Interaction logic for Chats.xaml
	/// </summary>
	public partial class Chats : Window
	{
		ServerConnector connector = ServerConnector.Instance;
		public Chats()
		{
			InitializeComponent();
		}

		private async void Button_Click(object sender, RoutedEventArgs e)
		{
		var result = await	connector.getPublicKey(recipient.Text);
			if(result == System.Net.HttpStatusCode.OK)
			{
				Chat chat = new Chat();
				chat.SetUserName(recipient.Text);
				chat.ShowDialog();
			}
		}
	
	}
}
