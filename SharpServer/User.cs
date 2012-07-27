using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Xml.Serialization;

namespace SharpServer
{
    [Serializable]
    public class User
    {
        [XmlAttribute("username")]
        public string UserName { get; set; }

        [XmlAttribute("password")]
        public string Password { get; set; }

        [XmlAttribute("homedir")]
        public string HomeDir { get; set; }

        [XmlIgnore]
        public bool IsAnonymous { get; set; }
    }

    [Obsolete]
    public static class UserStore
    {
        private static List<User> _users;

        static UserStore()
        {
            _users = new List<User>();

            XmlSerializer serializer = new XmlSerializer(_users.GetType(), new XmlRootAttribute("Users"));

            if (File.Exists("users.xml"))
            {
                _users = serializer.Deserialize(new StreamReader("users.xml")) as List<User>;
            }
            else
            {
                _users.Add(new User
                {
                    UserName = "rick",
                    Password = "test",
                    HomeDir = "C:\\Utils"
                });

                using (StreamWriter w = new StreamWriter("users.xml"))
                {
                    serializer.Serialize(w, _users);
                }
            }
        }

        public static User Validate(string username, string password)
        {
            User user = (from u in _users where u.UserName == username && u.Password == password select u).SingleOrDefault();

            if (user == null)
            {
                user = new User
                {
                    UserName = username,
                    HomeDir = "C:\\Utils",
                    IsAnonymous = true
                };
            }

            return user;
        }
    }
}
