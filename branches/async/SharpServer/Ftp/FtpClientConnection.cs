using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Text.RegularExpressions;
using SharpServer.Localization;
using System.Resources;

namespace SharpServer.Ftp
{
    public class FtpClientConnection : ClientConnection
    {
        /// <summary>
        /// This class allows us to maintain a list of TcpListeners for reuse, so we don't run out of ports under heavy load.
        /// </summary>
        public static class PassiveListeners
        {
            private static readonly object _listLock = new object();
            private static Dictionary<AutoResetEvent, TcpListener> _listeners = new Dictionary<AutoResetEvent, TcpListener>();

            public static TcpListener GetListener(IPAddress ip)
            {
                TcpListener listener = null;

                lock (_listLock)
                {
                    listener = _listeners.FirstOrDefault(p => p.Key.WaitOne(TimeSpan.FromMilliseconds(10)) && ((IPEndPoint)p.Value.LocalEndpoint).Address.Equals(ip)).Value;

                    if (listener == null)
                    {
                        AutoResetEvent listenerLock = new AutoResetEvent(false);

                        listener = new TcpListener(ip, 0);

                        _listeners.Add(listenerLock, listener);
                    }
                }

                return listener;
            }

            public static void FreeListener(TcpListener listener)
            {
                AutoResetEvent sync = _listeners.SingleOrDefault(p => p.Value == listener).Key;

                sync.Set();
            }

            public static void ReleaseAll()
            {
                lock (_listLock)
                {
                    foreach (var listener in _listeners.Values)
                    {
                        listener.Stop();
                    }

                    _listeners.Clear();
                }
            }
        }

        private static class FtpResponses
        {
            public static readonly Response QUIT = new Response { Code = "221", Text = FtpReplies.QUIT, ShouldQuit = true };
            public static readonly Response UNABLE_TO_OPEN_DATA_CONNECTION = new Response { Code = "500", Text = FtpReplies.UNABLE_TO_OPEN_DATA_CONNECTION, ShouldQuit = true };

            public static readonly Response SYSTEM = new Response { Code = "215", ResourceManager = FtpReplies.ResourceManager, Text = "SYSTEM" };
            public static readonly Response SERVICE_READY = new Response { Code = "220", ResourceManager = FtpReplies.ResourceManager, Text = "SERVICE_READY" };
            public static readonly Response NOT_IMPLEMENTED = new Response { Code = "502", ResourceManager = FtpReplies.ResourceManager, Text = "NOT_IMPLEMENTED" };
            public static readonly Response NOT_IMPLEMENTED_FOR_PARAMETER = new Response { Code = "504", ResourceManager = FtpReplies.ResourceManager, Text = "NOT_IMPLEMENTED_FOR_PARAMETER" };
            public static readonly Response OK = new Response { Code = "200", ResourceManager = FtpReplies.ResourceManager, Text = "OK" };
            public static readonly Response LOGGED_IN = new Response { Code = "230", ResourceManager = FtpReplies.ResourceManager, Text = "LOGGED_IN" };
            public static readonly Response NOT_LOGGED_IN = new Response { Code = "530", ResourceManager = FtpReplies.ResourceManager, Text = "NOT_LOGGED_IN" };
            public static readonly Response USER_OK = new Response { Code = "331", ResourceManager = FtpReplies.ResourceManager, Text = "USER_OK" };
            public static readonly Response RENAME_FROM = new Response { Code = "350", ResourceManager = FtpReplies.ResourceManager, Text = "RENAME_FROM" };
            public static readonly Response FILE_NOT_FOUND = new Response { Code = "550", ResourceManager = FtpReplies.ResourceManager, Text = "FILE_NOT_FOUND" };
            public static readonly Response DIRECTORY_NOT_FOUND = new Response { Code = "550", ResourceManager = FtpReplies.ResourceManager, Text = "DIRECTORY_NOT_FOUND" };
            public static readonly Response DIRECTORY_EXISTS = new Response { Code = "550", ResourceManager = FtpReplies.ResourceManager, Text = "DIRECTORY_EXISTS" };
            public static readonly Response FILE_ACTION_COMPLETE = new Response { Code = "250", ResourceManager = FtpReplies.ResourceManager, Text = "FILE_ACTION_COMPLETE" };
            public static readonly Response FILE_ACTION_NOT_TAKEN = new Response { Code = "450", ResourceManager = FtpReplies.ResourceManager, Text = "FILE_ACTION_NOT_TAKEN" };
            public static readonly Response ENABLING_TLS = new Response { Code = "234", ResourceManager = FtpReplies.ResourceManager, Text = "ENABLING_TLS" };
            public static readonly Response TRANSFER_ABORTED = new Response { Code = "426", ResourceManager = FtpReplies.ResourceManager, Text = "TRANSFER_ABORTED" };
            public static readonly Response TRANSFER_SUCCESSFUL = new Response { Code = "226", ResourceManager = FtpReplies.ResourceManager, Text = "TRANSFER_SUCCESSFUL" };
            public static readonly Response UTF8_ENCODING_ON = new Response { Code = "200", ResourceManager = FtpReplies.ResourceManager, Text = "UTF8_ENCODING_ON" };

            public static readonly Response ENTERING_PASSIVE_MODE = new Response { Code = "227", ResourceManager = FtpReplies.ResourceManager, Text = "ENTERING_PASSIVE_MODE" };
            public static readonly Response ENTERING_EXTENDED_PASSIVE_MODE = new Response { Code = "229", ResourceManager = FtpReplies.ResourceManager, Text = "ENTERING_EXTENDED_PASSIVE_MODE" };
            public static readonly Response PARAMETER_NOT_RECOGNIZED = new Response { Code = "501", ResourceManager = FtpReplies.ResourceManager, Text = "PARAMETER_NOT_RECOGNIZED" };
            public static readonly Response OPENING_DATA_TRANSFER = new Response { Code = "150", ResourceManager = FtpReplies.ResourceManager, Text = "OPENING_DATA_TRANSFER" };
            public static readonly Response CURRENT_DIRECTORY = new Response { Code = "257", ResourceManager = FtpReplies.ResourceManager, Text = "CURRENT_DIRECTORY" };

            public static readonly Response FEATURES = new Response { Code = "211-", Text = string.Format("{0}:\r\n MDTM\r\n SIZE\r\n UTF8\r\n211 End", FtpReplies.EXTENSIONS_SUPPORTED) };
        }

        private class DataConnectionOperation
        {
            public Func<NetworkStream, string, Response> Operation { get; set; }
            public string Arguments { get; set; }
        }

        #region Enums

        private enum TransferType
        {
            Ascii,
            Ebcdic,
            Image,
            Local,
        }

        private enum FormatControlType
        {
            NonPrint,
            Telnet,
            CarriageControl,
        }

        private enum DataConnectionType
        {
            Passive,
            Active,
        }

        private enum FileStructureType
        {
            File,
            Record,
            Page,
        }

        #endregion

        private const int BUFFER_SIZE = 8096;

        private TcpListener _passiveListener;
        private TcpClient _dataClient;
        private TransferType _connectionType = TransferType.Ascii;
        private FormatControlType _formatControlType = FormatControlType.NonPrint;
        private DataConnectionType _dataConnectionType = DataConnectionType.Active;
        private FileStructureType _fileStructureType = FileStructureType.File;

        private string _username;
        private string _root;
        private string _currentDirectory;
        private IPEndPoint _dataEndpoint;
        private X509Certificate _cert = null;
        private SslStream _sslStream;

        private bool _disposed = false;

        private bool _connected = false;

        private User _currentUser;
        private List<string> _validCommands;

        private static readonly Regex _invalidPathChars = new Regex(string.Join("|", Path.GetInvalidPathChars().Select(c => string.Format(CultureInfo.InvariantCulture, "\\u{0:X4}", (int)c))), RegexOptions.Compiled);

        private string _renameFrom;

        private Encoding _currentEncoding = Encoding.ASCII;
        private CultureInfo _currentCulture = CultureInfo.CurrentCulture;

        public FtpClientConnection()
            : base()
        {
            _validCommands = new List<string>();
            _renameFrom = null;
        }

        #region Overrides

        protected override Response HandleCommand(Command cmd)
        {
            Response response = null;

            FtpLogEntry logEntry = new FtpLogEntry
            {
                Date = DateTime.Now,
                CIP = ClientIP,
                CSUriStem = cmd.RawArguments
            };

            if (!_validCommands.Contains(cmd.Code))
            {
                response = CheckUser();
            }

            // Reset rename from if we don't receive a rename to command. These must be issued back-to-back.
            if (cmd.Code != "RNTO")
            {
                _renameFrom = null;
            }

            if (response == null)
            {
                switch (cmd.Code)
                {
                    case "USER":
                        response = User(cmd.Arguments.FirstOrDefault());
                        break;
                    case "PASS":
                        response = Password(cmd.Arguments.FirstOrDefault());
                        logEntry.CSUriStem = "******";
                        break;
                    case "CWD":
                        response = ChangeWorkingDirectory(cmd.Arguments.FirstOrDefault());
                        break;
                    case "CDUP":
                        response = ChangeWorkingDirectory("..");
                        break;
                    case "QUIT":
                        response = FtpResponses.QUIT.SetCulture(_currentCulture);
                        break;
                    case "REIN":
                        _currentUser = null;
                        _username = null;
                        _dataClient = null;
                        _currentCulture = CultureInfo.CurrentCulture;
                        _currentEncoding = Encoding.ASCII;
                        ControlStreamEncoding = Encoding.ASCII;

                        response = FtpResponses.SERVICE_READY.SetCulture(_currentCulture);
                        break;
                    case "PORT":
                        response = Port(cmd.RawArguments);
                        logEntry.CPort = _dataEndpoint.Port.ToString(CultureInfo.InvariantCulture);
                        break;
                    case "PASV":
                        response = Passive();
                        logEntry.SPort = ((IPEndPoint)_passiveListener.LocalEndpoint).Port.ToString(CultureInfo.InvariantCulture);
                        break;
                    case "TYPE":
                        response = Type(cmd.Arguments.FirstOrDefault(), cmd.Arguments.Skip(1).FirstOrDefault());
                        break;
                    case "STRU":
                        response = Structure(cmd.Arguments.FirstOrDefault());
                        break;
                    case "MODE":
                        response = Mode(cmd.Arguments.FirstOrDefault());
                        break;
                    case "RNFR":
                        _renameFrom = cmd.Arguments.FirstOrDefault();
                        response = FtpResponses.RENAME_FROM.SetCulture(_currentCulture);
                        break;
                    case "RNTO":
                        response = Rename(_renameFrom, cmd.Arguments.FirstOrDefault());
                        break;
                    case "DELE":
                        response = Delete(cmd.Arguments.FirstOrDefault());
                        break;
                    case "RMD":
                        response = RemoveDir(cmd.Arguments.FirstOrDefault());
                        break;
                    case "MKD":
                        response = CreateDir(cmd.Arguments.FirstOrDefault());
                        break;
                    case "PWD":
                        response = PrintWorkingDirectory();
                        break;
                    case "RETR":
                        response = Retrieve(cmd.Arguments.FirstOrDefault());
                        logEntry.Date = DateTime.Now;
                        break;
                    case "STOR":
                        response = Store(cmd.Arguments.FirstOrDefault());
                        logEntry.Date = DateTime.Now;
                        break;
                    case "STOU":
                        response = StoreUnique();
                        logEntry.Date = DateTime.Now;
                        break;
                    case "APPE":
                        response = Append(cmd.Arguments.FirstOrDefault());
                        logEntry.Date = DateTime.Now;
                        break;
                    case "LIST":
                        response = List(cmd.Arguments.FirstOrDefault() ?? _currentDirectory);
                        logEntry.Date = DateTime.Now;
                        break;
                    case "SYST":
                        response = FtpResponses.SYSTEM.SetCulture(_currentCulture);
                        break;
                    case "NOOP":
                        response = FtpResponses.OK.SetCulture(_currentCulture);;
                        break;
                    case "ACCT":
                        response = FtpResponses.OK.SetCulture(_currentCulture);;
                        break;
                    case "ALLO":
                        response = FtpResponses.OK.SetCulture(_currentCulture);;
                        break;
                    case "NLST":
                        response = NameList(cmd.Arguments.FirstOrDefault() ?? _currentDirectory);
                        break;
                    case "SITE":
                        response = FtpResponses.NOT_IMPLEMENTED.SetCulture(_currentCulture);;
                        break;
                    case "STAT":
                        response = FtpResponses.NOT_IMPLEMENTED.SetCulture(_currentCulture);;
                        break;
                    case "HELP":
                        response = FtpResponses.NOT_IMPLEMENTED.SetCulture(_currentCulture);;
                        break;
                    case "SMNT":
                        response = FtpResponses.NOT_IMPLEMENTED.SetCulture(_currentCulture);;
                        break;
                    case "REST":
                        response = FtpResponses.NOT_IMPLEMENTED.SetCulture(_currentCulture);;
                        break;
                    case "ABOR":
                        response = FtpResponses.NOT_IMPLEMENTED.SetCulture(_currentCulture);;
                        break;

                    // Extensions defined by rfc 2228
                    case "AUTH":
                        response = Auth(cmd.Arguments.FirstOrDefault());
                        break;

                    // Extensions defined by rfc 2389
                    case "FEAT":
                        response = FtpResponses.FEATURES.SetCulture(_currentCulture);;
                        break;
                    case "OPTS":
                        response = Options(cmd.Arguments);
                        break;

                    // Extensions defined by rfc 3659
                    case "MDTM":
                        response = FileModificationTime(cmd.Arguments.FirstOrDefault());
                        break;
                    case "SIZE":
                        response = FileSize(cmd.Arguments.FirstOrDefault());
                        break;

                    // Extensions defined by rfc 2428
                    case "EPRT":
                        response = EPort(cmd.RawArguments);
                        logEntry.CPort = _dataEndpoint.Port.ToString(CultureInfo.InvariantCulture);
                        break;
                    case "EPSV":
                        response = EPassive();
                        logEntry.SPort = ((IPEndPoint)_passiveListener.LocalEndpoint).Port.ToString(CultureInfo.InvariantCulture);
                        break;

                    // Extensions defined by rfc 2640
                    case "LANG":
                        response = Language(cmd.Arguments.FirstOrDefault());
                        break;

                    default:
                        response = FtpResponses.NOT_IMPLEMENTED.SetCulture(_currentCulture);;
                        break;
                }
            }

            logEntry.CSMethod = cmd.Code;
            logEntry.CSUsername = _username;
            logEntry.SCStatus = response.Code;

            _log.Info(logEntry);

            return response;
        }

        protected override void OnConnected()
        {
            FtpPerformanceCounters.IncrementCurrentConnections();

            _connected = true;

            Write(FtpResponses.SERVICE_READY.SetCulture(_currentCulture));

            _validCommands.AddRange(new string[] { "AUTH", "USER", "PASS", "QUIT", "HELP", "NOOP" });
            _dataClient = new TcpClient();

            Read();
        }

        protected override void OnCommandComplete(Command cmd)
        {
            if (cmd.Code == "AUTH")
            {
                _cert = new X509Certificate("server2.cer");

                _sslStream = new SslStream(ControlStream);

                _sslStream.AuthenticateAsServer(_cert);
            }

            FtpPerformanceCounters.IncrementCommandsExecuted();
        }

        protected override void Dispose(bool disposing)
        {
            try
            {
                if (!_disposed)
                {
                    _disposed = true;

                    if (_currentUser != null)
                        if (_currentUser.IsAnonymous)
                            FtpPerformanceCounters.DecrementAnonymousUsers();
                        else
                            FtpPerformanceCounters.DecrementNonAnonymousUsers();

                    if (_connected)
                        FtpPerformanceCounters.DecrementCurrentConnections();

                    if (disposing)
                    {
                        if (_dataClient != null)
                        {
                            _dataClient.Close();
                            _dataClient = null;
                        }

                        if (_sslStream != null)
                        {
                            _sslStream.Dispose();
                            _sslStream = null;
                        }
                    }
                }
            }
            finally
            {
                base.Dispose(disposing);
            }
        }

        protected override void Read()
        {
            if (_sslStream != null)
            {
                Read(_sslStream);
            }
            else
            {
                Read(ControlStream);
            }
        }

        protected override void Write(string content)
        {
            if (_sslStream != null)
            {
                Write(_sslStream, content);
            }
            else
            {
                Write(ControlStream, content);
            }
        }

        #endregion

        private bool IsPathValid(string path)
        {
            return path.StartsWith(_root, StringComparison.OrdinalIgnoreCase);
        }

        private string NormalizeFilename(string path)
        {
            if (path == null)
            {
                path = string.Empty;
            }

            if (_invalidPathChars.IsMatch(path))
            {
                return null;
            }

            if (path == "/")
            {
                return _root;
            }
            else if (path.StartsWith("/", StringComparison.OrdinalIgnoreCase))
            {
                path = new FileInfo(Path.Combine(_root, path.Substring(1))).FullName;
            }
            else
            {
                path = new FileInfo(Path.Combine(_currentDirectory, path)).FullName;
            }

            return IsPathValid(path) ? path : null;
        }

        private Response CheckUser()
        {
            if (_currentUser == null)
            {
                return FtpResponses.NOT_LOGGED_IN.SetCulture(_currentCulture);
            }

            return null;
        }

        private long CopyStream(Stream input, Stream output, Action<int> perfAction)
        {
            Stream limitedStream = output; // new RateLimitingStream(output, 131072, 0.5);

            if (_connectionType == TransferType.Image)
            {
                return CopyStream(input, limitedStream, BUFFER_SIZE, perfAction);
            }
            else
            {
                return CopyStream(input, limitedStream, BUFFER_SIZE, _currentEncoding, perfAction);
            }
        }

        #region FTP Commands

        /// <summary>
        /// USER Command - RFC 959 - Section 4.1.1
        /// </summary>
        /// <param name="username"></param>
        /// <returns></returns>
        private Response User(string username)
        {
            FtpPerformanceCounters.IncrementTotalLogonAttempts();

            _username = username;
            return FtpResponses.USER_OK.SetCulture(_currentCulture);
        }

        /// <summary>
        /// PASS Command - RFC 959 - Section 4.1.1
        /// </summary>
        /// <param name="username"></param>
        /// <returns></returns>
        private Response Password(string password)
        {
            _currentUser = UserStore.Validate(_username, password);

            if (_currentUser != null)
            {
                _root = _currentUser.HomeDir;
                _currentDirectory = _root;

                if (_currentUser.IsAnonymous)
                    FtpPerformanceCounters.IncrementAnonymousUsers();
                else
                    FtpPerformanceCounters.IncrementNonAnonymousUsers();

                return FtpResponses.LOGGED_IN.SetCulture(_currentCulture);
            }
            else
            {
                return FtpResponses.NOT_LOGGED_IN.SetCulture(_currentCulture);
            }
        }

        /// <summary>
        /// CWD Command - RFC 959 - Section 4.1.1
        /// </summary>
        /// <param name="username"></param>
        /// <returns></returns>
        private Response ChangeWorkingDirectory(string pathname)
        {
            if (pathname == "/")
            {
                _currentDirectory = _root;
            }
            else
            {
                string newDir;

                if (pathname.StartsWith("/", StringComparison.OrdinalIgnoreCase))
                {
                    pathname = pathname.Substring(1).Replace('/', '\\');
                    newDir = Path.Combine(_root, pathname);
                }
                else
                {
                    pathname = pathname.Replace('/', '\\');
                    newDir = Path.Combine(_currentDirectory, pathname);
                }

                if (Directory.Exists(newDir))
                {
                    _currentDirectory = new DirectoryInfo(newDir).FullName;

                    if (!IsPathValid(_currentDirectory))
                    {
                        _currentDirectory = _root;
                    }
                }
                else
                {
                    _currentDirectory = _root;
                }
            }

            return FtpResponses.OK.SetCulture(_currentCulture);
        }

        /// <summary>
        /// PORT Command - RFC 959 - Section 4.1.2
        /// </summary>
        /// <param name="username"></param>
        /// <returns></returns>
        private Response Port(string hostPort)
        {
            _dataConnectionType = DataConnectionType.Active;

            string[] ipAndPort = hostPort.Split(',');

            byte[] ipAddress = ipAndPort.Take(4).Select(s => Convert.ToByte(s, CultureInfo.InvariantCulture)).ToArray();
            byte[] port = ipAndPort.Skip(4).Select(s => Convert.ToByte(s, CultureInfo.InvariantCulture)).ToArray();

            if (BitConverter.IsLittleEndian)
                Array.Reverse(port);

            _dataEndpoint = new IPEndPoint(new IPAddress(ipAddress), BitConverter.ToInt16(port, 0));

            return FtpResponses.OK.SetCulture(_currentCulture);
        }

        private Response EPort(string hostPort)
        {
            _dataConnectionType = DataConnectionType.Active;

            char delimiter = hostPort[0];

            string[] rawSplit = hostPort.Split(new char[] { delimiter }, StringSplitOptions.RemoveEmptyEntries);

            char ipType = rawSplit[0][0];

            string ipAddress = rawSplit[1];
            string port = rawSplit[2];

            _dataEndpoint = new IPEndPoint(IPAddress.Parse(ipAddress), int.Parse(port));

            return FtpResponses.OK.SetCulture(_currentCulture);
        }

        /// <summary>
        /// PASV Command - RFC 959 - Section 4.1.2
        /// </summary>
        /// <param name="username"></param>
        /// <returns></returns>
        private Response Passive()
        {
            _dataConnectionType = DataConnectionType.Passive;

            IPAddress localIp = ((IPEndPoint)ControlClient.Client.LocalEndPoint).Address;

            _passiveListener = PassiveListeners.GetListener(localIp);

            try
            {
                _passiveListener.Start();
            }
            catch
            {
                _log.Error("No more ports available");
                return FtpResponses.UNABLE_TO_OPEN_DATA_CONNECTION.SetCulture(_currentCulture);
            }

            IPEndPoint passiveListenerEndpoint = (IPEndPoint)_passiveListener.LocalEndpoint;

            byte[] address = passiveListenerEndpoint.Address.GetAddressBytes();
            ushort port = (ushort)passiveListenerEndpoint.Port;

            byte[] portArray = BitConverter.GetBytes(port);

            if (BitConverter.IsLittleEndian)
                Array.Reverse(portArray);

            return FtpResponses.ENTERING_PASSIVE_MODE.SetData(address[0], address[1], address[2], address[3], portArray[0], portArray[1]).SetCulture(_currentCulture);
        }

        private Response EPassive()
        {
            _dataConnectionType = DataConnectionType.Passive;

            IPAddress localIp = ((IPEndPoint)ControlClient.Client.LocalEndPoint).Address;

            _passiveListener = PassiveListeners.GetListener(localIp);

            try
            {
                _passiveListener.Start();
            }
            catch
            {
                _log.Error("No more ports available");
                return FtpResponses.UNABLE_TO_OPEN_DATA_CONNECTION.SetCulture(_currentCulture);
            }

            IPEndPoint passiveListenerEndpoint = (IPEndPoint)_passiveListener.LocalEndpoint;

            return FtpResponses.ENTERING_EXTENDED_PASSIVE_MODE.SetData(passiveListenerEndpoint.Port).SetCulture(_currentCulture);
        }

        /// <summary>
        /// TYPE Command - RFC 959 - Section 4.1.2
        /// </summary>
        /// <param name="username"></param>
        /// <returns></returns>
        private Response Type(string typeCode, string formatControl)
        {
            switch (typeCode.ToUpperInvariant())
            {
                case "A":
                    _connectionType = TransferType.Ascii;
                    break;
                case "I":
                    _connectionType = TransferType.Image;
                    break;
                default:
                    return FtpResponses.NOT_IMPLEMENTED_FOR_PARAMETER.SetCulture(_currentCulture);
            }

            if (!string.IsNullOrWhiteSpace(formatControl))
            {
                switch (formatControl.ToUpperInvariant())
                {
                    case "N":
                        _formatControlType = FormatControlType.NonPrint;
                        break;
                    default:
                        return FtpResponses.NOT_IMPLEMENTED_FOR_PARAMETER.SetCulture(_currentCulture);
                }
            }

            return FtpResponses.OK.SetCulture(_currentCulture);
        }

        /// <summary>
        /// STRU Command - RFC 959 - Section 4.1.2
        /// </summary>
        /// <param name="username"></param>
        /// <returns></returns>
        private Response Structure(string structure)
        {
            switch (structure)
            {
                case "F":
                    _fileStructureType = FileStructureType.File;
                    break;
                case "R":
                case "P":
                    return FtpResponses.NOT_IMPLEMENTED_FOR_PARAMETER.SetCulture(_currentCulture);
                default:
                    return FtpResponses.PARAMETER_NOT_RECOGNIZED.SetData(structure).SetCulture(_currentCulture);
            }

            return FtpResponses.OK.SetCulture(_currentCulture);
        }

        /// <summary>
        /// MODE Command - RFC 959 - Section 4.1.2
        /// </summary>
        /// <param name="username"></param>
        /// <returns></returns>
        private Response Mode(string mode)
        {
            if (mode.ToUpperInvariant() == "S")
            {
                return FtpResponses.OK.SetCulture(_currentCulture);
            }
            else
            {
                return FtpResponses.NOT_IMPLEMENTED_FOR_PARAMETER.SetCulture(_currentCulture);
            }
        }

        /// <summary>
        /// RETR Command - RFC 959 - Section 4.1.3
        /// </summary>
        /// <param name="username"></param>
        /// <returns></returns>
        private Response Retrieve(string pathname)
        {
            pathname = NormalizeFilename(pathname);

            if (pathname != null)
            {
                if (File.Exists(pathname))
                {
                    var state = new DataConnectionOperation { Arguments = pathname, Operation = RetrieveOperation };

                    SetupDataConnectionOperation(state);

                    return FtpResponses.OPENING_DATA_TRANSFER.SetData(_dataConnectionType, "RETR").SetCulture(_currentCulture);
                }
            }

            return FtpResponses.FILE_NOT_FOUND.SetCulture(_currentCulture);
        }

        /// <summary>
        /// STOR Command - RFC 959 - Section 4.1.3
        /// </summary>
        /// <param name="username"></param>
        /// <returns></returns>
        private Response Store(string pathname)
        {
            pathname = NormalizeFilename(pathname);

            if (pathname != null)
            {
                var state = new DataConnectionOperation { Arguments = pathname, Operation = StoreOperation };

                SetupDataConnectionOperation(state);

                return FtpResponses.OPENING_DATA_TRANSFER.SetData(_dataConnectionType, "STOR").SetCulture(_currentCulture);
            }

            return FtpResponses.FILE_ACTION_NOT_TAKEN.SetCulture(_currentCulture);
        }

        /// <summary>
        /// STOU Command - RFC 959 - Section 4.1.3
        /// </summary>
        /// <param name="username"></param>
        /// <returns></returns>
        private Response StoreUnique()
        {
            string pathname = NormalizeFilename(new Guid().ToString());

            var state = new DataConnectionOperation { Arguments = pathname, Operation = StoreOperation };

            SetupDataConnectionOperation(state);

            return FtpResponses.OPENING_DATA_TRANSFER.SetData(_dataConnectionType, "STOU").SetCulture(_currentCulture);
        }

        /// <summary>
        /// APPE Command - RFC 959 - Section 4.1.3
        /// </summary>
        /// <param name="username"></param>
        /// <returns></returns>
        private Response Append(string pathname)
        {
            pathname = NormalizeFilename(pathname);

            if (pathname != null)
            {
                var state = new DataConnectionOperation { Arguments = pathname, Operation = AppendOperation };

                SetupDataConnectionOperation(state);

                return FtpResponses.OPENING_DATA_TRANSFER.SetData(_dataConnectionType, "APPE").SetCulture(_currentCulture);
            }

            return FtpResponses.FILE_ACTION_NOT_TAKEN.SetCulture(_currentCulture);
        }

        /// <summary>
        /// RNFR - RNTO - RFC 959 - Seciton 4.1.3
        /// </summary>
        /// <param name="renameFrom"></param>
        /// <param name="renameTo"></param>
        /// <returns></returns>
        private Response Rename(string renameFrom, string renameTo)
        {
            if (string.IsNullOrWhiteSpace(renameFrom) || string.IsNullOrWhiteSpace(renameTo))
            {
                return FtpResponses.FILE_ACTION_NOT_TAKEN.SetCulture(_currentCulture);
            }

            renameFrom = NormalizeFilename(renameFrom);
            renameTo = NormalizeFilename(renameTo);

            if (renameFrom != null && renameTo != null)
            {
                if (File.Exists(renameFrom))
                {
                    File.Move(renameFrom, renameTo);
                }
                else if (Directory.Exists(renameFrom))
                {
                    Directory.Move(renameFrom, renameTo);
                }
                else
                {
                    return FtpResponses.FILE_ACTION_NOT_TAKEN.SetCulture(_currentCulture);
                }

                return FtpResponses.FILE_ACTION_COMPLETE.SetCulture(_currentCulture);
            }

            return FtpResponses.FILE_ACTION_NOT_TAKEN.SetCulture(_currentCulture);
        }

        /// <summary>
        /// DELE Command - RFC 959 - Section 4.1.3
        /// </summary>
        /// <param name="username"></param>
        /// <returns></returns>
        private Response Delete(string pathname)
        {
            pathname = NormalizeFilename(pathname);

            if (pathname != null)
            {
                if (File.Exists(pathname))
                {
                    File.Delete(pathname);
                }
                else
                {
                    return FtpResponses.FILE_NOT_FOUND.SetCulture(_currentCulture);
                }

                return FtpResponses.FILE_ACTION_COMPLETE.SetCulture(_currentCulture);
            }

            return FtpResponses.FILE_NOT_FOUND.SetCulture(_currentCulture);
        }

        /// <summary>
        /// RMD Command - RFC 959 - Section 4.1.3
        /// </summary>
        /// <param name="username"></param>
        /// <returns></returns>
        private Response RemoveDir(string pathname)
        {
            pathname = NormalizeFilename(pathname);

            if (pathname != null)
            {
                if (Directory.Exists(pathname))
                {
                    Directory.Delete(pathname);
                }
                else
                {
                    return FtpResponses.DIRECTORY_NOT_FOUND.SetCulture(_currentCulture);
                }

                return FtpResponses.FILE_ACTION_COMPLETE.SetCulture(_currentCulture);
            }

            return FtpResponses.DIRECTORY_NOT_FOUND.SetCulture(_currentCulture);
        }

        /// <summary>
        /// MKD Command - RFC 959 - Section 4.1.3
        /// </summary>
        /// <param name="username"></param>
        /// <returns></returns>
        private Response CreateDir(string pathname)
        {
            pathname = NormalizeFilename(pathname);

            if (pathname != null)
            {
                if (!Directory.Exists(pathname))
                {
                    Directory.CreateDirectory(pathname);
                }
                else
                {
                    return FtpResponses.DIRECTORY_EXISTS.SetCulture(_currentCulture);
                }

                return FtpResponses.FILE_ACTION_COMPLETE.SetCulture(_currentCulture);
            }

            return FtpResponses.DIRECTORY_NOT_FOUND.SetCulture(_currentCulture);
        }

        /// <summary>
        /// PWD Command - RFC 959 - Section 4.1.3
        /// </summary>
        /// <param name="username"></param>
        /// <returns></returns>
        private Response PrintWorkingDirectory()
        {
            string current = _currentDirectory.Replace(_root, string.Empty).Replace('\\', '/');

            if (current.Length == 0)
            {
                current = "/";
            }

            return FtpResponses.CURRENT_DIRECTORY.SetData(current).SetCulture(_currentCulture);
        }

        private Response NameList(string pathname)
        {
            pathname = NormalizeFilename(pathname);

            if (pathname != null)
            {
                var state = new DataConnectionOperation { Arguments = pathname, Operation = NameListOperation };

                SetupDataConnectionOperation(state);

                return FtpResponses.OPENING_DATA_TRANSFER.SetData(_dataConnectionType, "NLST").SetCulture(_currentCulture);
            }

            return FtpResponses.FILE_ACTION_NOT_TAKEN.SetCulture(_currentCulture);
        }


        /// <summary>
        /// LIST Command - RFC 959 - Section 4.1.3
        /// </summary>
        /// <param name="username"></param>
        /// <returns></returns>
        private Response List(string pathname)
        {
            pathname = NormalizeFilename(pathname);

            if (pathname != null)
            {
                var state = new DataConnectionOperation { Arguments = pathname, Operation = ListOperation };

                SetupDataConnectionOperation(state);

                return FtpResponses.OPENING_DATA_TRANSFER.SetData(_dataConnectionType, "LIST").SetCulture(_currentCulture);
            }

            return FtpResponses.FILE_ACTION_NOT_TAKEN.SetCulture(_currentCulture);
        }

        /// <summary>
        /// AUTH Command - RFC 2228 - Section 3
        /// </summary>
        /// <param name="authMode"></param>
        /// <returns></returns>
        private Response Auth(string authMode)
        {
            if (authMode == "TLS")
            {
                return FtpResponses.ENABLING_TLS.SetCulture(_currentCulture);
            }
            else
            {
                return FtpResponses.NOT_IMPLEMENTED_FOR_PARAMETER.SetCulture(_currentCulture);
            }
        }

        /// <summary>
        /// OPTS Command - RFC 2389 - Section 4
        /// </summary>
        /// <param name="arguments">command-name [ SP command-options ]</param>
        /// <returns></returns>
        private Response Options(List<string> arguments)
        {
            if (arguments.FirstOrDefault() == "UTF8" && arguments.Skip(1).FirstOrDefault() == "ON")
            {
                _currentEncoding = Encoding.UTF8;
                ControlStreamEncoding = Encoding.UTF8;

                return FtpResponses.UTF8_ENCODING_ON.SetCulture(_currentCulture);
            }

            return FtpResponses.OK.SetCulture(_currentCulture);
        }

        /// <summary>
        /// MDTM Command - RFC 3659 - Section 3
        /// </summary>
        /// <param name="username"></param>
        /// <returns></returns>
        private Response FileModificationTime(string pathname)
        {
            pathname = NormalizeFilename(pathname);

            if (pathname != null)
            {
                if (File.Exists(pathname))
                {
                    return new Response { Code = "213", Text = File.GetLastWriteTime(pathname).ToString("yyyyMMddHHmmss.fff", CultureInfo.InvariantCulture) };
                }
            }

            return FtpResponses.FILE_NOT_FOUND.SetCulture(_currentCulture);
        }

        /// <summary>
        /// SIZE Command - RFC 3659 - Section 4
        /// </summary>
        /// <param name="username"></param>
        /// <returns></returns>
        private Response FileSize(string pathname)
        {
            pathname = NormalizeFilename(pathname);

            if (pathname != null)
            {
                if (File.Exists(pathname))
                {
                    long length = 0;

                    using (FileStream fs = File.Open(pathname, FileMode.Open, FileAccess.Read, FileShare.Read))
                    {
                        length = fs.Length;
                    }

                    return new Response { Code = "213", Text = length.ToString(CultureInfo.InvariantCulture) };
                }
            }

            return FtpResponses.FILE_NOT_FOUND.SetCulture(_currentCulture);
        }

        /// <summary>
        /// LANG Command - RFC 2640 - Section 4
        /// </summary>
        /// <param name="lang"></param>
        /// <returns></returns>
        private Response Language(string language)
        {
            try
            {
                var culture = CultureInfo.GetCultureInfo(language);

                ResourceSet rs = FtpReplies.ResourceManager.GetResourceSet(culture, true, false);

                if (rs == null)
                {
                    _currentCulture = CultureInfo.CurrentCulture;
                    return new Response { Code = "504", Text = "Language not implemented, using en-US" };
                }
                else
                {
                    _currentCulture = culture;

                    return new Response { Code = "200", Text = "Changed language to what you asked for" };
                }
            }
            catch
            {
                _currentCulture = CultureInfo.CurrentCulture;
                return new Response { Code = "500", Text = "Invalid language, using en-US" };
            }
        }

        #endregion

        #region DataConnection Operations

        private void HandleAsyncResult(IAsyncResult result)
        {
            if (_dataConnectionType == DataConnectionType.Active)
            {
                _dataClient.EndConnect(result);
            }
            else
            {
                _dataClient = _passiveListener.EndAcceptTcpClient(result);
            }
        }

        private void SetupDataConnectionOperation(DataConnectionOperation state)
        {
            if (_dataConnectionType == DataConnectionType.Active)
            {
                _dataClient = new TcpClient(_dataEndpoint.AddressFamily);
                _dataClient.BeginConnect(_dataEndpoint.Address, _dataEndpoint.Port, DoDataConnectionOperation, state);
            }
            else
            {
                _passiveListener.BeginAcceptTcpClient(DoDataConnectionOperation, state);
            }
        }

        private void DoDataConnectionOperation(IAsyncResult result)
        {
            FtpPerformanceCounters.IncrementTotalConnectionAttempts();
            FtpPerformanceCounters.IncrementCurrentConnections();

            HandleAsyncResult(result);

            DataConnectionOperation op = result.AsyncState as DataConnectionOperation;

            Response response;

            try
            {
                using (NetworkStream dataStream = _dataClient.GetStream())
                {
                    response = op.Operation(dataStream, op.Arguments);
                }
            }
            catch (Exception ex)
            {
                _log.Error(ex);
                response = FtpResponses.TRANSFER_ABORTED.SetCulture(_currentCulture);
            }

            if (_dataClient != null)
            {
                _dataClient.Close();
                _dataClient = null;
            }

            FtpPerformanceCounters.DecrementCurrentConnections();

            if (_dataConnectionType == DataConnectionType.Passive)
                PassiveListeners.FreeListener(_passiveListener);

            Write(response.ToString());
        }

        private Response RetrieveOperation(NetworkStream dataStream, string pathname)
        {
            using (FileStream fs = new FileStream(pathname, FileMode.Open, FileAccess.Read))
            {
                CopyStream(fs, dataStream, FtpPerformanceCounters.IncrementBytesSent);
            }

            FtpPerformanceCounters.IncrementFilesSent();

            return FtpResponses.TRANSFER_SUCCESSFUL.SetCulture(_currentCulture);
        }

        private Response StoreOperation(NetworkStream dataStream, string pathname)
        {
            long bytes = 0;

            using (FileStream fs = new FileStream(pathname, FileMode.OpenOrCreate, FileAccess.Write, FileShare.None, BUFFER_SIZE, FileOptions.SequentialScan))
            {
                bytes = CopyStream(dataStream, fs, FtpPerformanceCounters.IncrementBytesReceived);
            }

            FtpLogEntry logEntry = new FtpLogEntry
            {
                Date = DateTime.Now,
                CIP = ClientIP,
                CSMethod = "STOR",
                CSUsername = _username,
                SCStatus = "226",
                CSBytes = bytes.ToString(CultureInfo.InvariantCulture)
            };

            _log.Info(logEntry);

            FtpPerformanceCounters.IncrementFilesReceived();

            return FtpResponses.TRANSFER_SUCCESSFUL.SetCulture(_currentCulture);
        }

        private Response AppendOperation(NetworkStream dataStream, string pathname)
        {
            long bytes = 0;

            using (FileStream fs = new FileStream(pathname, FileMode.Append, FileAccess.Write, FileShare.None, BUFFER_SIZE, FileOptions.SequentialScan))
            {
                bytes = CopyStream(dataStream, fs, FtpPerformanceCounters.IncrementBytesReceived);
            }

            FtpLogEntry logEntry = new FtpLogEntry
            {
                Date = DateTime.Now,
                CIP = ClientIP,
                CSMethod = "APPE",
                CSUsername = _username,
                SCStatus = "226",
                CSBytes = bytes.ToString(CultureInfo.InvariantCulture)
            };

            _log.Info(logEntry);

            FtpPerformanceCounters.IncrementFilesReceived();

            return FtpResponses.TRANSFER_SUCCESSFUL.SetCulture(_currentCulture);
        }

        private Response ListOperation(NetworkStream dataStream, string pathname)
        {
            DateTime now = DateTime.Now;

            StreamWriter dataWriter = new StreamWriter(dataStream, _currentEncoding);

            IEnumerable<string> directories = Directory.EnumerateDirectories(pathname);

            foreach (string dir in directories)
            {
                DateTime editDate = Directory.GetLastWriteTime(dir);

                string date = editDate < now.Subtract(TimeSpan.FromDays(180)) ?
                    editDate.ToString("MMM dd  yyyy", CultureInfo.InvariantCulture) :
                    editDate.ToString("MMM dd HH:mm", CultureInfo.InvariantCulture);

                dataWriter.Write("drwxr-xr-x    2 2003     2003         4096 ");
                dataWriter.Write(date);
                dataWriter.Write(' ');
                dataWriter.WriteLine(Path.GetFileName(dir));

                dataWriter.Flush();
            }

            IEnumerable<string> files = Directory.EnumerateFiles(pathname);

            foreach (string file in files)
            {
                FileInfo f = new FileInfo(file);

                string date = f.LastWriteTime < now.Subtract(TimeSpan.FromDays(180)) ?
                    f.LastWriteTime.ToString("MMM dd  yyyy", CultureInfo.InvariantCulture) :
                    f.LastWriteTime.ToString("MMM dd HH:mm", CultureInfo.InvariantCulture);

                dataWriter.Write("-rw-r--r--    2 2003     2003     ");

                string length = f.Length.ToString(CultureInfo.InvariantCulture);

                if (length.Length < 8)
                {
                    for (int i = 0; i < 8 - length.Length; i++)
                    {
                        dataWriter.Write(' ');
                    }
                }

                dataWriter.Write(length);
                dataWriter.Write(' ');
                dataWriter.Write(date);
                dataWriter.Write(' ');
                dataWriter.WriteLine(f.Name);

                dataWriter.Flush();

                f = null;
            }

            FtpLogEntry logEntry = new FtpLogEntry
            {
                Date = now,
                CIP = ClientIP,
                CSMethod = "LIST",
                CSUsername = _username,
                SCStatus = "226"
            };

            _log.Info(logEntry);

            return FtpResponses.TRANSFER_SUCCESSFUL.SetCulture(_currentCulture);
        }

        private Response NameListOperation(NetworkStream dataStream, string pathname)
        {
            StreamWriter dataWriter = new StreamWriter(dataStream, _currentEncoding);

            IEnumerable<string> files = Directory.EnumerateFiles(pathname);

            foreach (string file in files)
            {
                dataWriter.WriteLine(Path.GetFileName(file));
                dataWriter.Flush();
            }

            FtpLogEntry logEntry = new FtpLogEntry
            {
                Date = DateTime.Now,
                CIP = ClientIP,
                CSMethod = "NLST",
                CSUsername = _username,
                SCStatus = "226"
            };

            _log.Info(logEntry);

            return FtpResponses.TRANSFER_SUCCESSFUL.SetCulture(_currentCulture);
        }

        #endregion
    }
}
