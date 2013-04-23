    public class DeskAuthenticationExample : System.Web.UI.Page
    {
        /// <summary>
        /// A class that captures the attributes required when passing a JSON object to Desk.
        /// </summary>
        protected class UserData
        {
            // Unique string of the user. This is the unique identifier of the user in your system, such as their guid or auto incremented id.
            // REQUIRED
            public string uid;

            //  Multipass expiration date in ISO 8601 format. This is for security purposes to expire the hash after a given period of time.
            // REQUIRED
            public string expires;

            // Absolute URL to redirect the user after successful login. If this is not supplied, users are either redirected to the original
            // page they were viewing/attempting to view on your portal, or they are redirected to your portal's home.
            // OPTIONAL
            //public string to;

            // Customer's email address
            // REQUIRED
            public string customer_email;

            // Customer's name
            // REQUIRED
            public string customer_name;

            // Custom attributes.  Use custom attributes to pass extra information about the customer to the Desk site.
            // Examples are shown below.
            // public string customer_custom_siteid;    // custom fields
            // public string customer_custom_sitename;    // add your own as needed
        }

        /*
         * Class constants
         */
        private const string api_key = "MyAPIKey";
        private const string site_key = "MySiteKey";
        private const int multipass_timeout_minutes = 60;  // 60 minute timeout on the Multipass

        protected void Page_Load(object sender, EventArgs e)
        {
            UserData user_data = new UserData();

            // Load user_data object with the required attributes.
            user_data.uid = "userID";
            user_data.expires = DateTime.UtcNow.AddMinutes(multipass_timeout_minutes).ToString("o"); // ISO 8601 referenced to Zulu.
            user_data.customer_email = "user@email.com";
            user_data.customer_name = "Test User";

            // Encrypt the user_data.  Encrypted token that is returned has the IV pre-prended to it.
            var encryptedMultipassToken = EncryptData(user_data);
            var encryptedMultipassTokenURLencoded = HttpUtility.UrlEncode(encryptedMultipassToken);

            // Generate the signature.
            var tokenSignature = SignToken(encryptedMultipassToken);
            var tokenSignatureURLencoded = HttpUtility.UrlEncode(tokenSignature);

            var deskSSO_url = string.Format("http://callemall.desk.com/customer/authentication/multipass/callback?multipass={0}&signature={1}",
                encryptedMultipassTokenURLencoded,
                tokenSignatureURLencoded
                );

            Response.Redirect(deskSSO_url);
        }


        /// <summary>
        /// Encrypts a JSON representation of a UserData object using AES128-CBC with a 16-bit SHA1 salted hash key.
        /// Returns a Base64 String containing the encrypted JSON pre-pended with the initialization vector (IV) used in the encryption.
        /// </summary>
        /// <param name="user_data">The UserData object to be encrypted.</param>
        /// <returns></returns>
        protected static string EncryptData(UserData user_data)
        {
            // Using byte arrays instead of strings
            byte[] encrypted;
            byte[] saltedHash;
            byte[] bIV = new byte[16];  // 16-byte initialization vector as a byte array.
            byte[] bJsonUserData;
            /* Uncomment to enable decrypting for debugging/testing
            byte[] decrypted = null;
             */

            // Encode the user_data object into a JSON string
            JavaScriptSerializer s = new JavaScriptSerializer();
            string json_data = s.Serialize(user_data);
            bJsonUserData = Encoding.ASCII.GetBytes(json_data);

            // Generate a random initialization vector
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            rng.GetBytes(bIV);

            // Use an AesManaged object to do the encryption
            using (AesManaged aesAlg = new AesManaged())
            {
                aesAlg.IV = bIV;
                aesAlg.KeySize = 128;

                // Create the 16-byte salted hash
                SHA1 sha1 = SHA1.Create();
                saltedHash = sha1.ComputeHash(Encoding.ASCII.GetBytes(api_key + site_key), 0, (api_key + site_key).Length);
                // Trim saltedHash to 16 bytes.
                Array.Resize(ref saltedHash, 16);

                // Use salted has as the AES key.
                aesAlg.Key = saltedHash;

                // Encrypt using the AES Managed object
                ICryptoTransform encryptor = aesAlg.CreateEncryptor();
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(bJsonUserData, 0, bJsonUserData.Length);
                        csEncrypt.FlushFinalBlock();
                    }
                    encrypted = msEncrypt.ToArray();
                }

                /*
                 * Uncomment to enable decrypting for debugging/testing
                 * 
                // Decrypt using AES Managed object
                ICryptoTransform decryptor = aesAlg.CreateDecryptor();
                using (MemoryStream msDecrypt = new MemoryStream())
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Write))
                    {
                        csDecrypt.Write(encrypted, 0, encrypted.Length);
                        csDecrypt.FlushFinalBlock();
                    }
                    decrypted = msDecrypt.ToArray();
                }
                
                string decryptedString = Encoding.ASCII.GetString(decrypted);
                 */
            }

            // Pre-pend the encrypted data with the IV.
            byte[] ivPlusEncrypted = bIV.Concat(encrypted).ToArray();

            // Return the Base64-encoded encrypted data
            string encryptedBase64 = Convert.ToBase64String(ivPlusEncrypted, Base64FormattingOptions.None);
            return encryptedBase64;
        }

        /// <summary>
        /// Creates and returns an HMAC-SHA1 signature of a String.
        /// </summary>
        /// <param name="token">The String that will be used to create the signature.</param>
        /// <returns></returns>
        protected static string SignToken(string token)
        {
            byte[] hash;

            using (HMACSHA1 hmacsha1 = new HMACSHA1(Encoding.ASCII.GetBytes(api_key)))
            {
                hash = hmacsha1.ComputeHash(Encoding.ASCII.GetBytes(token));
            }

            return Convert.ToBase64String(hash);
        }
    }
