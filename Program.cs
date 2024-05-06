using System;

namespace ICE
{
    internal class Program
    {
        static void Main()
        {
            PrintBanner();
            string constructedToken = Script.ConstructToken();
            Console.WriteLine("\nMy token: " + constructedToken);
            Console.Write("\nEnter token: ");
            string enteredToken = Console.ReadLine().Trim();
            if (enteredToken.Equals(constructedToken, StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine("You cannot enter your own token.");
                Console.WriteLine("Press any key to close.");
                Console.ReadKey();
            }
            else
            {
                try
                {
                    while (true)
                    {
                        Console.Write("\n127.0.0.1:80> ");
                        string command = Console.ReadLine().Trim();
                        if (command.Equals("/help", StringComparison.OrdinalIgnoreCase))
                        {
                            PrintHelp();
                        }
                        else if (command.StartsWith("/send", StringComparison.OrdinalIgnoreCase))
                        {
                            SendFile(enteredToken);
                        }
                        else if (command.StartsWith("/receive", StringComparison.OrdinalIgnoreCase))
                        {
                            ReceiveFile(enteredToken);
                        }
                        else
                        {
                            Console.WriteLine("Invalid command. Enter '/help' for usage information.");
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error: " + ex.Message);
                }
            }
        }

        static void PrintBanner()
        {
            Console.Title = "root";
            Console.WriteLine(@"░▒▓███████▓▒░░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓███████▓▒░      ░▒▓█▓▒░░▒▓██████▓▒░░▒▓████████▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░             ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░             ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░        
░▒▓█▓▒░░▒▓█▓▒░▒▓██████▓▒░  ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░       ░▒▓█▓▒░▒▓█▓▒░      ░▒▓██████▓▒░   
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░        
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓███████▓▒░       ░▒▓█▓▒░░▒▓██████▓▒░░▒▓████████▓▒░");
            Console.WriteLine("\nWhere Data Glides Unseen, \nEnd-to-End, Unraveled Dreams \n");
            Console.WriteLine("Always use [/] prefix when using commands \nType \"/help\" to see all commands");
        }

        static void PrintHelp()
        {
            Console.WriteLine("\nCommand list:");
            Console.WriteLine("/send - Initiates the sending process. You'll be prompted later to enter the path of the file to send.");
            Console.WriteLine("/receive - Initiates the receiving process. You'll be prompted later to enter the path where the received file will be saved.");
        }

        static async void SendFile(string token)
        {
            try
            {
                await Sender.SendFileAsync(token);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
                Console.WriteLine("Press any key to close.");
                Console.ReadKey();
            }
        }

        static async void ReceiveFile(string token)
        {
            try
            {
                await Receiver.ReceiveFileAsync(token);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
                Console.WriteLine("Press any key to close.");
                Console.ReadKey();
            }
        }
    }
}
