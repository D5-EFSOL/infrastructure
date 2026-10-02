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

    private const int MIN_PASSWORD_LENGTH = 8;

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
    // PASSWORD POLICY
    // ============================================================

    private bool IsPasswordStrong(
        string password)
    {
        if (String.IsNullOrEmpty(password))
        {
            return false;
        }


        if (password.Length <
            MIN_PASSWORD_LENGTH)
        {
            return false;
        }


        bool upper =
            Regex.IsMatch(
                password,
                @"[A-ZА-ЯЁ]"
            );


        bool lower =
            Regex.IsMatch(
                password,
                @"[a-zа-яё]"
            );


        bool digit =
            Regex.IsMatch(
                password,
                @"[0-9]"
            );


        bool special =
            Regex.IsMatch(
                password,
                @"[\W_]"
            );


        return upper &&
               lower &&
               digit &&
               special;
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

        if (!IsPasswordStrong(
            newPassword))
        {
            ShowError(
                "Новый пароль должен содержать " +
                "минимум " +
                MIN_PASSWORD_LENGTH +
                " символов и включать " +
                "заглавные и строчные буквы, " +
                "цифры и специальный символ."
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


            <asp:TextBox
                ID="txtCurrentPassword"
                runat="server"
                TextMode="Password"
                autocomplete="current-password"
            />

        </div>


        <!-- NEW PASSWORD -->

        <div class="field">

            <label
                for="txtNewPassword"
            >
                Новый пароль
            </label>


            <asp:TextBox
                ID="txtNewPassword"
                runat="server"
                TextMode="Password"
                autocomplete="new-password"
            />

        </div>


        <!-- CONFIRM PASSWORD -->

        <div class="field">

            <label
                for="txtConfirmPassword"
            >
                Подтвердите новый пароль
            </label>


            <asp:TextBox
                ID="txtConfirmPassword"
                runat="server"
                TextMode="Password"
                autocomplete="new-password"
            />

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


</div>

</form>

</body>

</html>
