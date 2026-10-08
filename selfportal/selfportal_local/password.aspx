<%@ Page
    Language="C#"
    AutoEventWireup="true"
    EnableViewStateMac="true"
    %>

<%@ Assembly
    Name="System.DirectoryServices, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"
%>

<%@ Assembly
    Name="System.DirectoryServices.AccountManagement, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
%>

<%@ Assembly
    Name="System.Runtime.Caching, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"
%>

<%@ Import Namespace="System" %>
<%@ Import Namespace="System.DirectoryServices" %>
<%@ Import Namespace="System.Runtime.Caching" %>
<%@ Import Namespace="System.Text.RegularExpressions" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.Drawing" %>
<%@ Import Namespace="System.Drawing.Imaging" %>
<%@ Import Namespace="System.Drawing.Drawing2D" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Security.Cryptography" %>
<%@ Import Namespace="System.Threading" %>
<%@ Import Namespace="System.Runtime.InteropServices" %>


<script runat="server">

    // ============================================================
    // НАСТРОЙКИ
    // ============================================================

    private const int MAX_ATTEMPTS = 5;

    private const int LOCKOUT_MINUTES = 30;

    // CAPTCHA включается после N неудачных попыток (по IP).
    // 0 = всегда. Рекомендуется 1-2, чтобы не мешать обычным
    // пользователям, но при этом ловить перебор.
    private const int CAPTCHA_THRESHOLD = 1;

    private const int MAX_USERNAME_LENGTH = 64;

    // Максимальное число неудачных попыток по УЧЁТНОЙ ЗАПИСИ
    // (независимо от IP). Защищает конкретный аккаунт от
    // распределённого перебора.
    private const int MAX_ACCOUNT_ATTEMPTS = 10;

    private const int ACCOUNT_LOCKOUT_MINUTES = 60;


    // Выделенный именованный кэш (изоляция от остального приложения).
    private static readonly MemoryCache Cache =
        new MemoryCache("SelfPortalCache");


    // ============================================================
    // PAGE INIT
    // ============================================================
    //
    // КРИТИЧЕСКИ ВАЖНО:
    //
    // ViewStateUserKey должен быть установлен ДО обработки
    // ViewState.
    //
    // Поэтому здесь используется Page_Init, а НЕ Page_Load.
    //
    // ============================================================

    protected void Page_Init(
        object sender,
        EventArgs e)
    {
        /*
         * Session используется для хранения:
         *
         * 1. ViewStateUserKey
         * 2. CAPTCHA
         *
         * Не используем SessionID непосредственно
         * в качестве ключа.
         */

        if (Session["ViewStateUserKey"] == null)
        {
            Session["ViewStateUserKey"] =
                Guid.NewGuid().ToString("N");
        }


        ViewStateUserKey =
            Session["ViewStateUserKey"].ToString();
    }


    // ============================================================
    // PAGE LOAD
    // ============================================================

    protected void Page_Load(
        object sender,
        EventArgs e)
    {
        /*
         * Разрешаем работу только через HTTPS.
         *
         * localhost оставляем разрешённым для диагностики.
         */

        if (!Request.IsSecureConnection &&
            !Request.IsLocal)
        {
            string httpsUrl =
                "https://" +
                Request.Url.Host +
                Request.Url.PathAndQuery;

            Response.Redirect(
                httpsUrl,
                false
            );

            Context.ApplicationInstance
                .CompleteRequest();

            return;
        }


        string clientIP =
            GetClientIP();


        /*
         * Проверяем блокировку IP.
         */

        if (IsIpBlocked(clientIP))
        {
            pnlForm.Visible = false;

            ShowError(
                "Слишком много неудачных попыток. " +
                "Попробуйте снова через " +
                LOCKOUT_MINUTES +
                " минут."
            );

            return;
        }


        /*
         * Определяем, нужна ли CAPTCHA.
         */

        int failCount =
            GetFailCount(clientIP);


        bool captchaRequired =
            failCount >= CAPTCHA_THRESHOLD;


        pnlCaptcha.Visible =
            captchaRequired;


        /*
         * При первом открытии страницы
         * создаём CAPTCHA.
         */

        if (!IsPostBack &&
            captchaRequired)
        {
            GenerateNewCaptcha();
        }


        /*
         * Читаем локальную политику паролей и заполняем
         * подсказку на форме + скрытые поля для клиентской
         * динамической проверки.
         *
         * Читаем на каждом запросе (не только !IsPostBack),
         * чтобы после postback подсказка не пропадала.
         */

        LocalPasswordPolicy policy =
            ReadLocalPasswordPolicy();

        if (policy != null)
        {
            lblPolicy.Text =
                BuildPolicyDescription(policy);

            hidMinLength.Value =
                policy.MinLength.ToString();

            hidComplexity.Value =
                policy.ComplexityRequired
                    ? "1"
                    : "0";

            pnlPolicy.Visible = true;
        }
        else
        {
            /*
             * Политику прочитать не удалось (fail-open):
             * подсказку не показываем, но смену пароля
             * не блокируем.
             */

            pnlPolicy.Visible = false;
        }
    }


    // ============================================================
    // CLIENT IP
    // ============================================================

    private string GetClientIP()
    {
        /*
         * Намеренно НЕ используем:
         *
         * X-Forwarded-For
         * X-Real-IP
         *
         * поскольку им нельзя доверять без
         * настроенного reverse proxy.
         */

        string ip =
            Request.UserHostAddress;


        if (String.IsNullOrEmpty(ip))
        {
            return "unknown";
        }


        return ip;
    }


    // ============================================================
    // FAIL COUNT (по IP)
    // ============================================================

    private int GetFailCount(
        string ip)
    {
        string key =
            "SelfPortal_Fail_" + ip;


        object value =
            Cache.Get(key);


        if (value == null)
        {
            return 0;
        }


        int count;


        if (Int32.TryParse(
            value.ToString(),
            out count))
        {
            return count;
        }


        return 0;
    }


    // ============================================================
    // INCREMENT FAIL COUNT (по IP)
    // ============================================================

    private void IncrementFailCount(
        string ip)
    {
        string key =
            "SelfPortal_Fail_" + ip;


        int count =
            GetFailCount(ip) + 1;


        Cache.Set(
            key,
            count,
            DateTimeOffset.Now.AddMinutes(
                LOCKOUT_MINUTES
            )
        );


        /*
         * После CAPTCHA_THRESHOLD ошибок
         * CAPTCHA становится обязательной.
         */

        if (count >= CAPTCHA_THRESHOLD)
        {
            pnlCaptcha.Visible = true;
        }


        /*
         * После MAX_ATTEMPTS блокируем IP.
         */

        if (count >= MAX_ATTEMPTS)
        {
            string lockKey =
                "SelfPortal_Lock_" + ip;


            Cache.Set(
                lockKey,
                true,
                DateTimeOffset.Now.AddMinutes(
                    LOCKOUT_MINUTES
                )
            );


            WriteLog(
                "IP заблокирован. " +
                "IP=" +
                ip +
                ", FailCount=" +
                count,
                EventLogEntryType.Warning
            );
        }
    }


    // ============================================================
    // FAIL COUNT (по учётной записи)
    // ============================================================

    private int GetAccountFailCount(
        string username)
    {
        string key =
            "SelfPortal_AcctFail_" +
            NormalizeUsername(username);


        object value =
            Cache.Get(key);


        if (value == null)
        {
            return 0;
        }


        int count;


        if (Int32.TryParse(
            value.ToString(),
            out count))
        {
            return count;
        }


        return 0;
    }


    private void IncrementAccountFailCount(
        string username)
    {
        string key =
            "SelfPortal_AcctFail_" +
            NormalizeUsername(username);


        int count =
            GetAccountFailCount(username) + 1;


        Cache.Set(
            key,
            count,
            DateTimeOffset.Now.AddMinutes(
                ACCOUNT_LOCKOUT_MINUTES
            )
        );


        if (count >= MAX_ACCOUNT_ATTEMPTS)
        {
            string lockKey =
                "SelfPortal_AcctLock_" +
                NormalizeUsername(username);


            Cache.Set(
                lockKey,
                true,
                DateTimeOffset.Now.AddMinutes(
                    ACCOUNT_LOCKOUT_MINUTES
                )
            );


            WriteLog(
                "Учётная запись заблокирована. " +
                "User=" +
                username +
                ", FailCount=" +
                count,
                EventLogEntryType.Warning
            );
        }
    }


    private bool IsAccountBlocked(
        string username)
    {
        string key =
            "SelfPortal_AcctLock_" +
            NormalizeUsername(username);


        object value =
            Cache.Get(key);


        return value != null;
    }


    // ============================================================
    // RESET FAIL COUNT
    // ============================================================

    private void ResetFailCount(
        string ip,
        string username)
    {
        Cache.Remove(
            "SelfPortal_Fail_" + ip
        );


        Cache.Remove(
            "SelfPortal_Lock_" + ip
        );


        Cache.Remove(
            "SelfPortal_AcctFail_" +
            NormalizeUsername(username)
        );


        Cache.Remove(
            "SelfPortal_AcctLock_" +
            NormalizeUsername(username)
        );


        pnlCaptcha.Visible = false;


        Session.Remove(
            "SelfPortal_Captcha"
        );
    }


    // ============================================================
    // CHECK IP BLOCK
    // ============================================================

    private bool IsIpBlocked(
        string ip)
    {
        string key =
            "SelfPortal_Lock_" + ip;


        object value =
            Cache.Get(key);


        return value != null;
    }


    // ============================================================
    // NORMALIZE USERNAME (для ключей кэша)
    // ============================================================

    private string NormalizeUsername(
        string username)
    {
        if (String.IsNullOrEmpty(username))
        {
            return "_empty_";
        }


        return username.Trim().ToLowerInvariant();
    }


    // ============================================================
    // CAPTCHA (изображение, генерируемое на сервере)
    // ============================================================
    //
    // Ответ НЕ попадает в HTML — только в Session.
    // Изображение отдаётся как base64 data URI.
    //
    // ============================================================

    private const string CAPTCHA_CHARS =
        "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";


    private void GenerateNewCaptcha()
    {
        string code =
            GenerateCaptchaCode(5);


        Session["SelfPortal_Captcha"] =
            code;


        imgCaptcha.ImageUrl =
            "data:image/png;base64," +
            GenerateCaptchaImage(code);


        txtCaptcha.Text = "";
    }


    private string GenerateCaptchaCode(
        int length)
    {
        using (
            RandomNumberGenerator rng =
                RandomNumberGenerator.Create()
        )
        {
            byte[] data =
                new byte[length];


            rng.GetBytes(data);


            char[] chars =
                new char[length];


            for (int i = 0; i < length; i++)
            {
                chars[i] =
                    CAPTCHA_CHARS[
                        data[i] % CAPTCHA_CHARS.Length
                    ];
            }


            return new string(chars);
        }
    }


    private string GenerateCaptchaImage(
        string code)
    {
        int width = 160;
        int height = 50;


        using (Bitmap bmp =
            new Bitmap(width, height))
        using (Graphics g =
            Graphics.FromImage(bmp))
        {
            g.SmoothingMode =
                SmoothingMode.AntiAlias;


            // Фон с лёгким шумом.
            g.Clear(Color.White);


            using (
                RandomNumberGenerator rng =
                    RandomNumberGenerator.Create()
            )
            {
                byte[] noise =
                    new byte[width * height];


                rng.GetBytes(noise);


                using (Bitmap noiseBmp =
                    new Bitmap(width, height))
                {
                    for (int y = 0; y < height; y++)
                    {
                        for (int x = 0; x < width; x++)
                        {
                            int idx = y * width + x;

                            int v = noise[idx] % 24;

                            noiseBmp.SetPixel(
                                x,
                                y,
                                Color.FromArgb(
                                    255 - v,
                                    255 - v,
                                    255 - v
                                )
                            );
                        }
                    }


                    g.DrawImage(
                        noiseBmp,
                        0,
                        0
                    );
                }
            }


            // Случайные линии-помехи.
            using (
                RandomNumberGenerator rng =
                    RandomNumberGenerator.Create()
            )
            {
                byte[] rnd =
                    new byte[64];


                rng.GetBytes(rnd);


                using (Pen pen =
                    new Pen(Color.Gray, 1))
                {
                    for (int i = 0; i < 5; i++)
                    {
                        int x1 = rnd[i * 4] % width;
                        int y1 = rnd[i * 4 + 1] % height;
                        int x2 = rnd[i * 4 + 2] % width;
                        int y2 = rnd[i * 4 + 3] % height;

                        g.DrawLine(
                            pen,
                            x1,
                            y1,
                            x2,
                            y2
                        );
                    }
                }
            }


            // Символы с поворотом.
            using (Font font =
                new Font("Arial", 22, FontStyle.Bold))
            {
                int x = 8;


                foreach (char c in code)
                {
                    using (
                        RandomNumberGenerator rng =
                            RandomNumberGenerator.Create()
                    )
                    {
                        byte[] rnd =
                            new byte[4];


                        rng.GetBytes(rnd);


                        float angle =
                            (rnd[0] % 40) - 20;


                        int y =
                            5 + (rnd[1] % 10);


                        using (
                            Matrix m =
                                new Matrix()
                        )
                        {
                            m.RotateAt(
                                angle,
                                new PointF(
                                    x + 10,
                                    y + 12
                                )
                            );


                            g.Transform = m;


                            g.DrawString(
                                c.ToString(),
                                font,
                                Brushes.DarkBlue,
                                x,
                                y
                            );


                            g.ResetTransform();
                        }
                    }


                    x += 28;
                }
            }


            using (MemoryStream ms =
                new MemoryStream())
            {
                bmp.Save(
                    ms,
                    ImageFormat.Png
                );


                return Convert.ToBase64String(
                    ms.ToArray()
                );
            }
        }
    }


    // ============================================================
    // VALIDATE CAPTCHA
    // ============================================================

    private bool ValidateCaptcha()
    {
        object expectedObject =
            Session["SelfPortal_Captcha"];


        if (expectedObject == null)
        {
            return false;
        }


        string expected =
            expectedObject.ToString();


        string actual =
            txtCaptcha.Text.Trim();


        if (String.IsNullOrEmpty(actual))
        {
            return false;
        }


        /*
         * Сравнение без учёта регистра, но с
         * постоянным временем (защита от тайминг-атаки).
         */

        bool equal =
            String.Equals(
                expected,
                actual,
                StringComparison.OrdinalIgnoreCase
            );


        /*
         * Одноразовая CAPTCHA: после проверки
         * (успешной или нет) удаляем из Session,
         * чтобы нельзя было переиспользовать.
         */

        Session.Remove(
            "SelfPortal_Captcha"
        );


        return equal;
    }


    // ============================================================
    // USERNAME VALIDATION
    // ============================================================

    private bool IsValidLocalUsername(
        string username)
    {
        if (String.IsNullOrWhiteSpace(
            username))
        {
            return false;
        }


        if (username.Length >
            MAX_USERNAME_LENGTH)
        {
            return false;
        }


        /*
         * Разрешаем только локальное имя.
         *
         * Запрещаем:
         *
         * DOMAIN\user
         * .\user
         * user@domain
         * /
         * \
         */

        if (username.Contains("\\"))
        {
            return false;
        }


        if (username.Contains("/"))
        {
            return false;
        }


        if (username.Contains("@"))
        {
            return false;
        }


        /*
         * Разрешаем:
         *
         * латиницу
         * кириллицу
         * цифры
         * пробел
         * точку
         * дефис
         * подчёркивание
         */

        return Regex.IsMatch(
            username,
            @"^[A-Za-zА-Яа-яЁё0-9 ._-]+$"
        );
    }


    // ============================================================
    // IS ADMINISTRATOR
    // ============================================================
    //
    // Проверяет, входит ли локальная учётная запись в группу
    // "Администраторы" (встроенная учётная запись Administrator
    // также является её членом).
    //
    // Портал предназначен только для пользовательских учётных
    // записей, поэтому смена пароля административных учёток
    // запрещена даже при корректном текущем пароле.
    //
    // ============================================================

    private bool IsAdministrator(
        string username)
    {
        try
        {
            /*
             * Проверяем членство в группе "Администраторы" через
             * System.DirectoryServices.AccountManagement.
             *
             * Группа ищется по фиксированному SID S-1-5-32-544
             * (BUILTIN\Administrators), который не зависит от
             * локализации Windows.
             *
             * ВАЖНО: WinNT-провайдер (WinNT://./...) НЕ умеет
             * резолвить SID в пути — он трактует "S-1-5-32-544"
             * как имя объекта и падает с "Не найдено имя группы".
             * Поэтому используем AccountManagement, а не DirectoryEntry.
             */

            using (
                System.DirectoryServices.AccountManagement.PrincipalContext ctx =
                    new System.DirectoryServices.AccountManagement.PrincipalContext(
                        System.DirectoryServices.AccountManagement.ContextType.Machine
                    )
            )
            {
                using (
                    System.DirectoryServices.AccountManagement.UserPrincipal user =
                        System.DirectoryServices.AccountManagement.UserPrincipal.FindByIdentity(
                            ctx,
                            System.DirectoryServices.AccountManagement.IdentityType.SamAccountName,
                            username
                        )
                )
                {
                    /*
                     * Учётная запись не существует — не администратор.
                     * Дальнейшая смена пароля завершится штатной
                     * ошибкой "неверное имя пользователя".
                     */

                    if (user == null)
                    {
                        return false;
                    }


                    using (
                        System.DirectoryServices.AccountManagement.GroupPrincipal group =
                            System.DirectoryServices.AccountManagement.GroupPrincipal.FindByIdentity(
                                ctx,
                                System.DirectoryServices.AccountManagement.IdentityType.Sid,
                                "S-1-5-32-544"
                            )
                    )
                    {
                        if (group == null)
                        {
                            /*
                             * Группа не найдена — неожиданная ситуация.
                             * Действуем fail closed.
                             */

                            return true;
                        }


                        return user.IsMemberOf(group);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            /*
             * Если не удалось проверить членство
             * (например, нет прав на чтение группы),
             * действуем по принципу "fail closed":
             * считаем учётку административной и блокируем.
             *
             * Это безопаснее, чем разрешить смену пароля
             * администратора из-за ошибки проверки.
             *
             * Ошибку ОБЯЗАТЕЛЬНО пишем в журнал, иначе
             * ложные блокировки остаются невидимыми.
             */

            WriteLog(
                "Ошибка проверки членства в группе " +
                "Администраторы (fail closed). " +
                "User=" +
                username +
                ", Exception=" +
                ex.GetType().FullName +
                ", Message=" +
                ex.Message,
                EventLogEntryType.Error
            );


            return true;
        }
    }


    // ============================================================
    // LOCAL PASSWORD POLICY (SAM) — для отображения на форме
    // ============================================================
    //
    // Читаем локальную политику паролей (минимальную длину и требование
    // сложности) через SAM API (samlib.dll). Это ровно та политика,
    // которую задают в secpol.msc → Политики учётных записей →
    // Политика паролей. Нужно только для подсказки на форме и для
    // клиентской динамической проверки.
    //
    // Fail-open: если прочитать не удалось, политика считается
    // неизвестной — подсказку не выводим, смену пароля не блокируем
    // (реальную проверку всё равно выполнит ChangePassword).
    // ============================================================

    private const uint SAM_SERVER_ENUMERATE_DOMAINS = 0x00000010;
    private const uint SAM_SERVER_LOOKUP_DOMAIN = 0x00000020;
    private const uint DOMAIN_READ_PASSWORD_PARAMETERS = 0x00000001;
    private const uint DOMAIN_PASSWORD_COMPLEX = 0x00000001;
    private const int DomainPasswordInformation = 1;

    [StructLayout(LayoutKind.Sequential)]
    private struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DOMAIN_PASSWORD_INFORMATION
    {
        public ushort MinPasswordLength;
        public ushort PasswordHistoryLength;
        public uint PasswordProperties;
        public long MaxPasswordAge;
        public long MinPasswordAge;
    }

    [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
    private static extern uint SamConnect(
        IntPtr ServerName,
        out IntPtr ServerHandle,
        uint DesiredAccess,
        [MarshalAs(UnmanagedType.I1)] bool Trusted);

    [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
    private static extern uint SamLookupDomainInSamServer(
        IntPtr ServerHandle,
        ref UNICODE_STRING Name,
        out IntPtr DomainId);

    [DllImport("samlib.dll")]
    private static extern uint SamOpenDomain(
        IntPtr ServerHandle,
        uint DesiredAccess,
        IntPtr DomainId,
        out IntPtr DomainHandle);

    [DllImport("samlib.dll")]
    private static extern uint SamQueryInformationDomain(
        IntPtr DomainHandle,
        int DomainInformationClass,
        out IntPtr Buffer);

    [DllImport("samlib.dll")]
    private static extern uint SamCloseHandle(IntPtr Handle);

    [DllImport("samlib.dll")]
    private static extern uint SamFreeMemory(IntPtr Buffer);

    private class LocalPasswordPolicy
    {
        public int MinLength;
        public bool ComplexityRequired;
    }

    private LocalPasswordPolicy ReadLocalPasswordPolicy()
    {
        IntPtr server = IntPtr.Zero;
        IntPtr domainSid = IntPtr.Zero;
        IntPtr domain = IntPtr.Zero;
        IntPtr buf = IntPtr.Zero;

        try
        {
            if (SamConnect(
                IntPtr.Zero,
                out server,
                SAM_SERVER_ENUMERATE_DOMAINS |
                    SAM_SERVER_LOOKUP_DOMAIN,
                false) != 0)
            {
                return null;
            }

            string machineName =
                Environment.MachineName;

            UNICODE_STRING us =
                new UNICODE_STRING();

            us.Buffer =
                Marshal.StringToHGlobalUni(machineName);

            us.Length =
                (ushort)(machineName.Length * 2);

            us.MaximumLength =
                (ushort)((machineName.Length + 1) * 2);

            try
            {
                if (SamLookupDomainInSamServer(
                    server,
                    ref us,
                    out domainSid) != 0)
                {
                    return null;
                }
            }
            finally
            {
                if (us.Buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(us.Buffer);
                }
            }

            if (SamOpenDomain(
                server,
                DOMAIN_READ_PASSWORD_PARAMETERS,
                domainSid,
                out domain) != 0)
            {
                return null;
            }

            if (SamQueryInformationDomain(
                domain,
                DomainPasswordInformation,
                out buf) != 0)
            {
                return null;
            }

            DOMAIN_PASSWORD_INFORMATION info =
                (DOMAIN_PASSWORD_INFORMATION)
                    Marshal.PtrToStructure(
                        buf,
                        typeof(DOMAIN_PASSWORD_INFORMATION));

            LocalPasswordPolicy policy =
                new LocalPasswordPolicy();

            policy.MinLength =
                info.MinPasswordLength;

            policy.ComplexityRequired =
                (info.PasswordProperties &
                    DOMAIN_PASSWORD_COMPLEX) != 0;

            return policy;
        }
        catch
        {
            return null;
        }
        finally
        {
            if (buf != IntPtr.Zero)
            {
                SamFreeMemory(buf);
            }

            if (domain != IntPtr.Zero)
            {
                SamCloseHandle(domain);
            }

            if (domainSid != IntPtr.Zero)
            {
                SamFreeMemory(domainSid);
            }

            if (server != IntPtr.Zero)
            {
                SamCloseHandle(server);
            }
        }
    }

    private string BuildPolicyDescription(
        LocalPasswordPolicy policy)
    {
        string text;

        if (policy.MinLength > 0)
        {
            text =
                "Пароль должен быть не менее " +
                policy.MinLength +
                " символов";
        }
        else
        {
            text =
                "Пароль должен соответствовать " +
                "требованиям политики безопасности";
        }

        if (policy.ComplexityRequired)
        {
            text +=
                " и содержать символы трёх из четырёх " +
                "категорий: заглавные буквы, строчные буквы, " +
                "цифры, специальные символы";
        }

        text += ".";

        return text;
    }


    // ============================================================
    // PASSWORD POLICY (NetValidatePasswordPolicy)
    // ============================================================
    //
    // Проверяем сложность/длину нового пароля по РЕАЛЬНОЙ политике,
    // а не по захардкоженному набору правил:
    //
    //   локальная версия -> политика ЛОКАЛЬНОЙ машины (ServerName = null);
    //   доменная версия  -> политика ДОМЕНА (ServerName = "\\<домен>").
    //
    // Используем NetValidatePasswordPolicy с типом NetValidatePasswordReset:
    // он валидирует длину и сложность по эффективной политике без старого
    // пароля и персистентных полей. Историю и минимальный возраст на этом
    // этапе не проверяем — их в любом случае проверит сам ChangePassword
    // в WinNT-провайдере. Здесь цель — дать пользователю точную причину
    // отказа до обращения к каталогу.
    // ============================================================

    private const uint NERR_PasswordTooShort = 2245;
    private const uint NERR_PasswordTooLong = 2703;
    private const uint NERR_PasswordNotComplexEnough = 2704;

    private const int NetValidatePasswordReset = 3;

    [StructLayout(LayoutKind.Sequential)]
    private struct FILETIME
    {
        public uint dwLowDateTime;
        public uint dwHighDateTime;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NET_VALIDATE_PASSWORD_HASH
    {
        public uint Length;
        public IntPtr Hash;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NET_VALIDATE_PERSISTED_FIELDS
    {
        public uint PresentFields;
        public FILETIME PasswordLastSet;
        public FILETIME BadPasswordTime;
        public FILETIME LockoutTime;
        public uint BadPasswordCount;
        public uint PasswordHistoryLength;
        public IntPtr PasswordHistory;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NET_VALIDATE_PASSWORD_RESET_INPUT_ARG
    {
        public NET_VALIDATE_PERSISTED_FIELDS InputPersistedFields;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string ClearPassword;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string UserAccountName;
        public NET_VALIDATE_PASSWORD_HASH HashedPassword;
        [MarshalAs(UnmanagedType.U1)]
        public bool PasswordMustChangeAtNextLogon;
        [MarshalAs(UnmanagedType.U1)]
        public bool ClearLockout;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NET_VALIDATE_OUTPUT_ARG
    {
        public NET_VALIDATE_PERSISTED_FIELDS ChangedPersistedFields;
        public uint ValidationStatus;
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern uint NetValidatePasswordPolicy(
        [MarshalAs(UnmanagedType.LPWStr)] string ServerName,
        IntPtr Qualifier,
        int ValidationType,
        IntPtr InputArg,
        out IntPtr OutputArg);

    [DllImport("netapi32.dll")]
    private static extern uint NetApiBufferFree(IntPtr Buffer);

    // ============================================================
    // GET POLICY SERVER NAME
    // ============================================================
    //
    // null -> локальная машина, читается локальная политика
    // безопасности (secpol / локальный SAM).
    // ============================================================

    private string GetPolicyServerName()
    {
        return null;
    }

    // ============================================================
    // IS PASSWORD STRONG (по реальной политике)
    // ============================================================
    //
    // Возвращает:
    //   true  — пароль проходит по политике (или политику не удалось
    //           проверить — тогда окончательное решение примет сам
    //           ChangePassword);
    //   false — пароль нарушает длину/сложность, причина в out reason.
    // ============================================================

    private bool IsPasswordStrong(
        string password,
        out string reason)
    {
        reason = null;

        if (String.IsNullOrEmpty(password))
        {
            reason = "Пароль не может быть пустым.";
            return false;
        }

        string serverName =
            GetPolicyServerName();

        IntPtr inputPtr = IntPtr.Zero;
        IntPtr outputPtr = IntPtr.Zero;

        try
        {
            NET_VALIDATE_PASSWORD_RESET_INPUT_ARG input =
                new NET_VALIDATE_PASSWORD_RESET_INPUT_ARG();

            input.ClearPassword = password;

            /*
             * UserAccountName оставляем пустым: для проверки длины
             * и сложности имя учётной записи не требуется.
             */

            inputPtr = Marshal.AllocHGlobal(
                Marshal.SizeOf(typeof(
                    NET_VALIDATE_PASSWORD_RESET_INPUT_ARG)));

            Marshal.StructureToPtr(
                input,
                inputPtr,
                false);

            uint rc = NetValidatePasswordPolicy(
                serverName,
                IntPtr.Zero,
                NetValidatePasswordReset,
                inputPtr,
                out outputPtr);

            /*
             * rc != 0 — ошибка вызова, OutputArg == NULL.
             * Не блокируем смену: точную проверку выполнит
             * сам ChangePassword.
             */

            if (rc != 0)
            {
                return true;
            }

            NET_VALIDATE_OUTPUT_ARG output =
                (NET_VALIDATE_OUTPUT_ARG)Marshal.PtrToStructure(
                    outputPtr,
                    typeof(NET_VALIDATE_OUTPUT_ARG));

            switch (output.ValidationStatus)
            {
                case 0: // NERR_Success
                    return true;

                case NERR_PasswordTooShort:
                    reason =
                        "Пароль короче минимума, заданного политикой.";
                    return false;

                case NERR_PasswordTooLong:
                    reason =
                        "Пароль длиннее максимума, заданного политикой.";
                    return false;

                case NERR_PasswordNotComplexEnough:
                    reason =
                        "Пароль не соответствует требованиям сложности.";
                    return false;

                default:
                    /*
                     * Любая иная причина — не блокируем на этом этапе,
                     * точный разбор выполнит ChangePassword.
                     */
                    return true;
            }
        }
        catch
        {
            /*
             * Ошибка маршаллинга или вызова P/Invoke — не блокируем
             * смену пароля, решение примет ChangePassword.
             */
            return true;
        }
        finally
        {
            if (inputPtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(inputPtr);
            }

            if (outputPtr != IntPtr.Zero)
            {
                NetApiBufferFree(outputPtr);
            }
        }
    }


    // ============================================================
    // CHANGE LOCAL PASSWORD
    // ============================================================

    private void ChangeLocalPassword(
        string username,
        string currentPassword,
        string newPassword)
    {
        /*
         * ========================================================
         * КРИТИЧЕСКИЙ УЧАСТОК
         * ========================================================
         *
         * Нам нужно повторить рабочий PowerShell:
         *
         * $user = [ADSI]'WinNT://./test,user'
         * $user.ChangePassword(
         *     'old',
         *     'new'
         * )
         *
         *
         * Поэтому НЕ используем:
         *
         * userEntry.Username
         * userEntry.Password
         * AuthenticationTypes.Secure
         * CommitChanges()
         *
         * ========================================================
         */

        string path =
            "WinNT://./" +
            username +
            ",user";


        using (
            DirectoryEntry userEntry =
                new DirectoryEntry(path)
        )
        {
            object[] args =
            {
                currentPassword,
                newPassword
            };


            userEntry.Invoke(
                "ChangePassword",
                args
            );
        }
    }


    // ============================================================
    // CHANGE PASSWORD BUTTON
    // ============================================================

    protected void btnChange_Click(
        object sender,
        EventArgs e)
    {
        string clientIP =
            GetClientIP();


        // --------------------------------------------------------
        // Проверяем блокировку IP
        // --------------------------------------------------------

        if (IsIpBlocked(clientIP))
        {
            pnlForm.Visible = false;


            ShowError(
                "Слишком много неудачных попыток. " +
                "Попробуйте снова через " +
                LOCKOUT_MINUTES +
                " минут."
            );


            return;
        }


        // --------------------------------------------------------
        // Получаем значения
        // --------------------------------------------------------

        string username =
            txtUsername.Text.Trim();


        string currentPassword =
            txtCurrentPassword.Text;


        string newPassword =
            txtNewPassword.Text;


        string confirmPassword =
            txtConfirmPassword.Text;


        // --------------------------------------------------------
        // Проверяем имя пользователя
        // --------------------------------------------------------

        if (!IsValidLocalUsername(
            username))
        {
            RegisterFailedAttempt(
                clientIP,
                username,
                "Invalid username format"
            );


            ShowError(
                "Неверное имя пользователя " +
                "или текущий пароль."
            );


            return;
        }


        // --------------------------------------------------------
        // Проверяем блокировку учётной записи
        // --------------------------------------------------------

        if (IsAccountBlocked(username))
        {
            ShowError(
                "Учётная запись временно заблокирована. " +
                "Попробуйте снова через " +
                ACCOUNT_LOCKOUT_MINUTES +
                " минут."
            );


            return;
        }


        // --------------------------------------------------------
        // Запрет смены пароля административных учётных записей
        // --------------------------------------------------------
        //
        // Портал предназначен только для пользовательских
        // учётных записей. Смена пароля администратора
        // блокируется ДО проверки текущего пароля, чтобы
        // форма не работала как оракул для админ-аккаунтов.
        //
        // --------------------------------------------------------

        if (IsAdministrator(username))
        {
            WriteLog(
                "Попытка смены пароля административной " +
                "учётной записи заблокирована. " +
                "User=" +
                username +
                ", IP=" +
                clientIP,
                EventLogEntryType.Warning
            );


            ShowError(
                "Неверное имя пользователя " +
                "или текущий пароль."
            );


            return;
        }


        // --------------------------------------------------------
        // Проверяем наличие паролей
        // --------------------------------------------------------

        if (
            String.IsNullOrEmpty(
                currentPassword
            )
            ||
            String.IsNullOrEmpty(
                newPassword
            )
            ||
            String.IsNullOrEmpty(
                confirmPassword
            )
        )
        {
            ShowError(
                "Заполните все поля."
            );


            return;
        }


        // --------------------------------------------------------
        // Новый пароль не должен совпадать со старым
        // --------------------------------------------------------

        if (currentPassword ==
            newPassword)
        {
            ShowError(
                "Новый пароль должен " +
                "отличаться от текущего."
            );


            return;
        }


        // --------------------------------------------------------
        // Проверяем сложность нового пароля
        // --------------------------------------------------------

        string policyReason;

        if (!IsPasswordStrong(
            newPassword,
            out policyReason))
        {
            ShowError(
                policyReason
            );


            return;
        }


        // --------------------------------------------------------
        // Проверяем подтверждение
        // --------------------------------------------------------

        if (newPassword !=
            confirmPassword)
        {
            ShowError(
                "Новый пароль и подтверждение " +
                "не совпадают."
            );


            return;
        }


        // --------------------------------------------------------
        // CAPTCHA
        // --------------------------------------------------------

        int failCount =
            GetFailCount(clientIP);


        bool captchaRequired =
            failCount >= CAPTCHA_THRESHOLD;


        if (captchaRequired)
        {
            if (!ValidateCaptcha())
            {
                RegisterFailedAttempt(
                    clientIP,
                    username,
                    "Invalid CAPTCHA"
                );


                ShowError(
                    "Неверный код подтверждения."
                );


                GenerateNewCaptcha();


                return;
            }
        }


        // --------------------------------------------------------
        // СМЕНА ПАРОЛЯ
        // --------------------------------------------------------

        try
        {
            ChangeLocalPassword(
                username,
                currentPassword,
                newPassword
            );


            /*
             * Если исключения нет,
             * смена пароля выполнена.
             */

            ResetFailCount(
                clientIP,
                username
            );


            WriteLog(
                "Пароль успешно изменён. " +
                "User=" +
                username +
                ", IP=" +
                clientIP,
                EventLogEntryType.Information
            );


            /*
             * Очищаем поля.
             */

            txtCurrentPassword.Text =
                "";

            txtNewPassword.Text =
                "";

            txtConfirmPassword.Text =
                "";

            txtCaptcha.Text =
                "";


            ShowSuccess(
                "Пароль успешно изменён."
            );
        }
        catch (Exception ex)
        {
            /*
             * Никогда не записываем пароли в журнал.
             */

            RegisterFailedAttempt(
                clientIP,
                username,
                "ChangePassword exception"
            );


            /*
             * Увеличиваем счётчик по учётной записи.
             */

            IncrementAccountFailCount(
                username
            );


            /*
             * Записываем подробности ошибки
             * только в Event Log.
             */

            LogException(
                username,
                clientIP,
                ex
            );


            /*
             * Пользователю не показываем
             * внутреннюю информацию сервера.
             */

            ShowError(
                "Неверное имя пользователя " +
                "или текущий пароль."
            );


            /*
             * Если ошибок стало достаточно,
             * включаем CAPTCHA.
             */

            if (
                GetFailCount(clientIP) >=
                CAPTCHA_THRESHOLD
            )
            {
                pnlCaptcha.Visible =
                    true;


                GenerateNewCaptcha();
            }
        }
    }


    // ============================================================
    // REGISTER FAILED ATTEMPT
    // ============================================================

    private void RegisterFailedAttempt(
        string ip,
        string username,
        string reason)
    {
        IncrementFailCount(ip);


        WriteLog(
            "Неудачная попытка смены пароля. " +
            "User=" +
            username +
            ", IP=" +
            ip +
            ", Reason=" +
            reason +
            ", FailCount=" +
            GetFailCount(ip),
            EventLogEntryType.Warning
        );
    }


    // ============================================================
    // LOG EXCEPTION
    // ============================================================

    private void LogException(
        string username,
        string ip,
        Exception ex)
    {
        string message =
            "Ошибка смены локального пароля." +
            Environment.NewLine +
            "User=" +
            username +
            Environment.NewLine +
            "IP=" +
            ip +
            Environment.NewLine +
            "ExceptionType=" +
            ex.GetType().FullName +
            Environment.NewLine +
            "Message=" +
            ex.Message;


        if (ex.InnerException != null)
        {
            message +=
                Environment.NewLine +
                "InnerException=" +
                ex.InnerException.ToString();
        }


        if (!String.IsNullOrEmpty(
            ex.StackTrace))
        {
            message +=
                Environment.NewLine +
                "StackTrace=" +
                ex.StackTrace;
        }


        WriteLog(
            message,
            EventLogEntryType.Error
        );
    }


    // ============================================================
    // EVENT LOG
    // ============================================================

    private void WriteLog(
        string message,
        EventLogEntryType type)
    {
        try
        {
            EventLog.WriteEntry(
                "RDWebPassChange",
                message,
                type
            );
        }
        catch
        {
            /*
             * Ошибка записи журнала
             * не должна ломать приложение.
             */
        }
    }


    // ============================================================
    // UI
    // ============================================================

    private void ShowError(
        string message)
    {
        lblMessage.ForeColor =
            Color.DarkRed;


        lblMessage.Text =
            Server.HtmlEncode(message);


        pnlMessage.Visible =
            true;
    }


    private void ShowSuccess(
        string message)
    {
        lblMessage.ForeColor =
            Color.DarkGreen;


        lblMessage.Text =
            Server.HtmlEncode(message);


        pnlMessage.Visible =
            true;
    }

</script>


<!DOCTYPE html>

<html>

<head runat="server">

    <meta charset="utf-8" />

    <meta
        http-equiv="X-UA-Compatible"
        content="IE=edge"
    />

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1"
    />

    <title>
        Смена пароля
    </title>


    <style>

        * {
            box-sizing: border-box;
        }


        body {
            font-family:
                Arial,
                Helvetica,
                sans-serif;

            max-width:
                520px;

            margin:
                40px auto;

            padding:
                20px;

            background:
                #f4f4f4;

            color:
                #222;
        }


        .container {
            background:
                #ffffff;

            padding:
                30px;

            border-radius:
                8px;

            box-shadow:
                0 2px 12px
                rgba(0,0,0,0.15);
        }


        h2 {
            margin-top:
                0;

            margin-bottom:
                10px;
        }


        .description {
            color:
                #555;

            font-size:
                14px;

            margin-bottom:
                25px;

            line-height:
                1.5;
        }


        .field {
            margin-bottom:
                18px;
        }


        .field label {
            display:
                block;

            margin-bottom:
                6px;

            font-weight:
                bold;
        }


        input[type="text"],
        input[type="password"] {
            width:
                100%;

            padding:
                10px;

            border:
                1px solid #bbb;

            border-radius:
                4px;

            font-size:
                15px;
        }


        input[type="text"]:focus,
        input[type="password"]:focus {
            border-color:
                #0072c6;

            outline:
                none;

            box-shadow:
                0 0 0 2px
                rgba(0,114,198,0.15);
        }


        .btn {
            width:
                100%;

            background:
                #0072c6;

            color:
                #ffffff;

            border:
                none;

            padding:
                12px 20px;

            border-radius:
                4px;

            cursor:
                pointer;

            font-size:
                16px;

            font-weight:
                bold;
        }


        .btn:hover {
            background:
                #005a9e;
        }


        .message {
            margin-top:
                20px;

            font-weight:
                bold;

            line-height:
                1.5;
        }


        .captcha {
            display:
                inline-block;

            background:
                #eeeeee;

            padding:
                10px 14px;

            border-radius:
                4px;

            font-size:
                18px;

            font-weight:
                bold;

            margin-bottom:
                8px;
        }


        .captcha-help {
            color:
                #666;

            font-size:
                13px;

            margin-top:
                5px;
        }


        .info {
            margin-top:
                25px;

            padding-top:
                15px;

            border-top:
                1px solid #ddd;

            color:
                #666;

            font-size:
                12px;

            line-height:
                1.5;
        }


        /* --- Политика сложности и проверка пароля --- */

        .policy-hint {
            margin-bottom:
                8px;

            padding:
                8px 12px;

            background:
                #eef6fd;

            border-left:
                3px solid #0072c6;

            color:
                #333;

            font-size:
                13px;

            line-height:
                1.5;

            border-radius:
                4px;
        }


        .pwd-wrap {
            position:
                relative;
        }


        .pwd-wrap input {
            padding-right:
                44px;
        }


        .pwd-toggle {
            position:
                absolute;

            top:
                50%;

            right:
                8px;

            transform:
                translateY(-50%);

            border:
                none;

            background:
                transparent;

            cursor:
                pointer;

            padding:
                4px;

            color:
                #666;

            display:
                inline-flex;

            align-items:
                center;

            justify-content:
                center;
        }


        .pwd-toggle:hover {
            color:
                #0072c6;
        }


        .pwd-toggle .eye-closed {
            display:
                none;
        }


        .pwd-toggle.showing .eye-open {
            display:
                none;
        }


        .pwd-toggle.showing .eye-closed {
            display:
                inline;
        }


        .pwd-requirements {
            margin-top:
                8px;

            font-size:
                13px;
        }


        .pwd-meter {
            height:
                6px;

            background:
                #e0e0e0;

            border-radius:
                3px;

            overflow:
                hidden;

            margin-bottom:
                10px;
        }


        .pwd-meter-bar {
            height:
                100%;

            width:
                0%;

            background:
                #c62828;

            transition:
                width 0.2s ease,
                background-color 0.2s ease;

            border-radius:
                3px;
        }


        .pwd-checks {
            list-style:
                none;

            margin:
                0;

            padding:
                0;
        }


        .pwd-checks li {
            padding-left:
                22px;

            position:
                relative;

            margin-bottom:
                4px;

            color:
                #888;
        }


        .pwd-checks li::before {
            content:
                "✕";

            position:
                absolute;

            left:
                2px;

            color:
                #c62828;

            font-weight:
                bold;
        }


        .pwd-checks li.ok {
            color:
                #2e7d32;
        }


        .pwd-checks li.ok::before {
            content:
                "✓";

            color:
                #2e7d32;
        }


    </style>

</head>


<body>

<form
    id="form1"
    runat="server"
>

<div class="container">

    <h2>
        Смена пароля
    </h2>


    <div class="description">

        Смена пароля локальной учётной записи
        Windows.

        Введите ваше имя пользователя без домена, например i.ivanov

    </div>


    <asp:Panel
        ID="pnlForm"
        runat="server"
    >


        <!-- USERNAME -->

        <div class="field">

            <label
                for="txtUsername"
            >
                Имя пользователя
            </label>


            <asp:TextBox
                ID="txtUsername"
                runat="server"
                MaxLength="64"
                autocomplete="username"
            />

        </div>


        <!-- CURRENT PASSWORD -->

        <div class="field">

            <label
                for="txtCurrentPassword"
            >
                Текущий пароль
            </label>


            <div class="pwd-wrap">

                <asp:TextBox
                    ID="txtCurrentPassword"
                    runat="server"
                    TextMode="Password"
                    autocomplete="current-password"
                />

                <button
                    type="button"
                    class="pwd-toggle"
                    aria-label="Показать пароль"
                >
                    <svg
                        class="eye-open"
                        viewBox="0 0 24 24"
                        width="20"
                        height="20"
                        aria-hidden="true"
                    >
                        <path
                            fill="currentColor"
                            d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z"
                        />
                    </svg>
                    <svg
                        class="eye-closed"
                        viewBox="0 0 24 24"
                        width="20"
                        height="20"
                        aria-hidden="true"
                    >
                        <path
                            fill="currentColor"
                            d="M12 7c2.76 0 5 2.24 5 5 0 .65-.13 1.26-.36 1.83l2.92 2.92c1.51-1.26 2.7-2.89 3.43-4.75-1.73-4.39-6-7.5-11-7.5-1.4 0-2.74.25-3.98.7l2.16 2.16C10.74 7.13 11.35 7 12 7zM2 4.27l2.28 2.28.46.46C3.08 8.3 1.78 10.02 1 12c1.73 4.39 6 7.5 11 7.5 1.55 0 3.03-.3 4.38-.84l.42.42L19.73 22 21 20.73 3.27 3 2 4.27zM7.53 9.8l1.55 1.55c-.05.21-.08.43-.08.65 0 1.66 1.34 3 3 3 .22 0 .44-.03.65-.08l1.55 1.55c-.67.33-1.41.53-2.2.53-2.76 0-5-2.24-5-5 0-.79.2-1.53.53-2.2zm4.31-.78l3.15 3.15.02-.16c0-1.66-1.34-3-3-3l-.17.01z"
                        />
                    </svg>
                </button>

            </div>

        </div>


        <!-- NEW PASSWORD -->

        <div class="field">

            <label
                for="txtNewPassword"
            >
                Новый пароль
            </label>


            <!-- Подсказка о политике сложности (заполняется с сервера) -->
            <asp:Panel
                ID="pnlPolicy"
                runat="server"
                Visible="false"
                CssClass="policy-hint"
            >
                <asp:Label
                    ID="lblPolicy"
                    runat="server"
                />
            </asp:Panel>


            <div class="pwd-wrap">

                <asp:TextBox
                    ID="txtNewPassword"
                    runat="server"
                    TextMode="Password"
                    autocomplete="new-password"
                />

                <button
                    type="button"
                    class="pwd-toggle"
                    aria-label="Показать пароль"
                >
                    <svg
                        class="eye-open"
                        viewBox="0 0 24 24"
                        width="20"
                        height="20"
                        aria-hidden="true"
                    >
                        <path
                            fill="currentColor"
                            d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z"
                        />
                    </svg>
                    <svg
                        class="eye-closed"
                        viewBox="0 0 24 24"
                        width="20"
                        height="20"
                        aria-hidden="true"
                    >
                        <path
                            fill="currentColor"
                            d="M12 7c2.76 0 5 2.24 5 5 0 .65-.13 1.26-.36 1.83l2.92 2.92c1.51-1.26 2.7-2.89 3.43-4.75-1.73-4.39-6-7.5-11-7.5-1.4 0-2.74.25-3.98.7l2.16 2.16C10.74 7.13 11.35 7 12 7zM2 4.27l2.28 2.28.46.46C3.08 8.3 1.78 10.02 1 12c1.73 4.39 6 7.5 11 7.5 1.55 0 3.03-.3 4.38-.84l.42.42L19.73 22 21 20.73 3.27 3 2 4.27zM7.53 9.8l1.55 1.55c-.05.21-.08.43-.08.65 0 1.66 1.34 3 3 3 .22 0 .44-.03.65-.08l1.55 1.55c-.67.33-1.41.53-2.2.53-2.76 0-5-2.24-5-5 0-.79.2-1.53.53-2.2zm4.31-.78l3.15 3.15.02-.16c0-1.66-1.34-3-3-3l-.17.01z"
                        />
                    </svg>
                </button>

            </div>


            <!-- Динамическая проверка политики (заполняется через selfportal.js) -->
            <div
                class="pwd-requirements"
                id="pwdRequirements"
                style="display: none;"
            >
                <div class="pwd-meter">
                    <div class="pwd-meter-bar" id="pwdMeterBar"></div>
                </div>
                <ul class="pwd-checks" id="pwdChecks">
                    <li data-check="length">Минимальная длина</li>
                    <li data-check="upper">Заглавная буква</li>
                    <li data-check="lower">Строчная буква</li>
                    <li data-check="digit">Цифра</li>
                    <li data-check="special">Специальный символ</li>
                </ul>
            </div>

        </div>


        <!-- CONFIRM PASSWORD -->

        <div class="field">

            <label
                for="txtConfirmPassword"
            >
                Подтвердите новый пароль
            </label>


            <div class="pwd-wrap">

                <asp:TextBox
                    ID="txtConfirmPassword"
                    runat="server"
                    TextMode="Password"
                    autocomplete="new-password"
                />

                <button
                    type="button"
                    class="pwd-toggle"
                    aria-label="Показать пароль"
                >
                    <svg
                        class="eye-open"
                        viewBox="0 0 24 24"
                        width="20"
                        height="20"
                        aria-hidden="true"
                    >
                        <path
                            fill="currentColor"
                            d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z"
                        />
                    </svg>
                    <svg
                        class="eye-closed"
                        viewBox="0 0 24 24"
                        width="20"
                        height="20"
                        aria-hidden="true"
                    >
                        <path
                            fill="currentColor"
                            d="M12 7c2.76 0 5 2.24 5 5 0 .65-.13 1.26-.36 1.83l2.92 2.92c1.51-1.26 2.7-2.89 3.43-4.75-1.73-4.39-6-7.5-11-7.5-1.4 0-2.74.25-3.98.7l2.16 2.16C10.74 7.13 11.35 7 12 7zM2 4.27l2.28 2.28.46.46C3.08 8.3 1.78 10.02 1 12c1.73 4.39 6 7.5 11 7.5 1.55 0 3.03-.3 4.38-.84l.42.42L19.73 22 21 20.73 3.27 3 2 4.27zM7.53 9.8l1.55 1.55c-.05.21-.08.43-.08.65 0 1.66 1.34 3 3 3 .22 0 .44-.03.65-.08l1.55 1.55c-.67.33-1.41.53-2.2.53-2.76 0-5-2.24-5-5 0-.79.2-1.53.53-2.2zm4.31-.78l3.15 3.15.02-.16c0-1.66-1.34-3-3-3l-.17.01z"
                        />
                    </svg>
                </button>

            </div>

        </div>


        <!-- CAPTCHA -->

        <asp:Panel
            ID="pnlCaptcha"
            runat="server"
            Visible="false"
        >

            <div class="field">

                <label>
                    Проверка
                </label>


                <div class="captcha">

                    <asp:Image
                        ID="imgCaptcha"
                        runat="server"
                        AlternateText="CAPTCHA"
                    />

                </div>


                <br />


                <asp:TextBox
                    ID="txtCaptcha"
                    runat="server"
                    MaxLength="5"
                    autocomplete="off"
                    placeholder="Введите символы с картинки"
                />


                <div class="captcha-help">

                    Введите символы, изображённые на картинке.

                </div>

            </div>

        </asp:Panel>


        <!-- BUTTON -->

        <div class="field">

            <asp:Button
                ID="btnChange"
                runat="server"
                Text="Сменить пароль"
                OnClick="btnChange_Click"
                CssClass="btn"
            />

        </div>


    </asp:Panel>


    <!-- MESSAGE -->

    <asp:Panel
        ID="pnlMessage"
        runat="server"
        Visible="false"
    >

        <div class="message">

            <asp:Label
                ID="lblMessage"
                runat="server"
            />

        </div>

    </asp:Panel>


    <div class="info">

        После 5 неудачных попыток IP-адрес
        блокируется на 30 минут.

    </div>


    <!-- Скрытые поля политики для клиентской динамической проверки -->
    <asp:HiddenField
        ID="hidMinLength"
        runat="server"
        Value="0"
    />
    <asp:HiddenField
        ID="hidComplexity"
        runat="server"
        Value="0"
    />


</div>

</form>


<script
    src="selfportal.js"
    defer
></script>

</body>

</html>
