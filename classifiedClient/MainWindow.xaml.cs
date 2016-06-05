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
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace classifiedClient
{
	/// <summary>
	/// Interaction logic for MainWindow.xaml
	/// </summary>
	public partial class MainWindow : Window
	{
		ServerConnector connector = ServerConnector.Instance;
		public MainWindow()
		{
			InitializeComponent();
		}

		private async void Button_Click(object sender, RoutedEventArgs e)
		{
		var result = await	connector.Register(userName.Text, password.Text);
			if(result == System.Net.HttpStatusCode.Created)
			{
				Chats chats = new Chats();
				chats.Show();
				this.Close();
			}
		}

		private async void Button_Click_1(object sender, RoutedEventArgs e)
		{
			var result = await connector.Login(userName.Text, password.Text);
			if(result == System.Net.HttpStatusCode.OK)
			{
				Chats chats = new Chats();
				chats.Show();
				this.Close();
			}
		}
	}
}
