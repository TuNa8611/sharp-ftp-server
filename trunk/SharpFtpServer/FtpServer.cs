using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Net.Sockets;
using System.IO;
using System.Threading;

using log4net;

namespace SharpFtpServer
{
    public class FtpServer : IDisposable
    {
        ILog _log = LogManager.GetLogger(typeof(FtpServer));

        private bool _disposed = false;
        private bool _listening = false;

        private TcpListener _listener;
        private List<ClientConnection> _activeConnections;

        public FtpServer()
        {
        }

        public void Start()
        {
            _listener = new TcpListener(IPAddress.Any, 21);

            _log.Info("#Version: 1.0");
            _log.Info("#Fields: date time c-ip c-port cs-username cs-method cs-uri-stem sc-status sc-bytes cs-bytes s-name s-port");

            _listening = true;
            _listener.Start();

            _activeConnections = new List<ClientConnection>();

            _listener.BeginAcceptTcpClient(HandleAcceptTcpClient, _listener);
        }

        public void Stop()
        {
            _log.Info("Stopping FtpServer");

            _listening = false;
            _listener.Stop();

            _listener = null;
        }

        private void HandleAcceptTcpClient(IAsyncResult result)
        {
            if (_listening)
            {
                _listener.BeginAcceptTcpClient(HandleAcceptTcpClient, _listener);

                TcpClient client = _listener.EndAcceptTcpClient(result);

                ClientConnection connection = new ClientConnection(client);

                _activeConnections.Add(connection);

                ThreadPool.QueueUserWorkItem(connection.HandleClient, client);
            }
        }

        public void Dispose()
        {
            Dispose(true);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    Stop();

                    foreach (ClientConnection conn in _activeConnections)
                    {
                        conn.Dispose();
                    }
                }
            }

            _disposed = true;
        }
    }
}
