/* ============================================================
 * SelfPortal — клиентская логика
 *   - «глазок» (показать/скрыть пароль)
 *   - динамическая проверка нового пароля (шкала + чек-лист)
 *   - проверка совпадения повтора пароля с подсветкой ошибки
 *   - блокировка кнопки до корректного заполнения всех полей
 *
 * Вся логика вынесена во внешний файл, т.к. CSP запрещает
 * inline-скрипты (script-src 'self').
 *
 * Работает с серверными полями (ClientID без префиксов, т.к.
 * Panel не является naming container):
 *   txtUsername, txtCurrentPassword, txtNewPassword,
 *   txtConfirmPassword, txtCaptcha,
 *   hidMinLength, hidComplexity, btnChange
 * ============================================================ */

(function () {
    "use strict";

    function $(id) {
        return document.getElementById(id);
    }

    /* ----------------------------------------------------------
     * 1. «Глазок» — показать/скрыть пароль
     * ---------------------------------------------------------- */

    function initEyeToggles() {
        var toggles = document.querySelectorAll(".pwd-toggle");
        var i;

        for (i = 0; i < toggles.length; i++) {
            (function (btn) {
                btn.addEventListener("click", function () {
                    var wrap = btn.parentNode;
                    var input = wrap.querySelector("input");

                    if (!input) {
                        return;
                    }

                    var showing = input.type === "text";

                    if (showing) {
                        input.type = "password";
                        btn.classList.remove("showing");
                        btn.setAttribute("aria-label", "Показать пароль");
                    } else {
                        input.type = "text";
                        btn.classList.add("showing");
                        btn.setAttribute("aria-label", "Скрыть пароль");
                    }
                });
            })(toggles[i]);
        }
    }

    /* ----------------------------------------------------------
     * 2. Политика паролей
     * ---------------------------------------------------------- */

    function getMinLength() {
        var el = $("hidMinLength");
        var v = el ? parseInt(el.value, 10) : 0;
        return isNaN(v) ? 0 : v;
    }

    function getComplexityRequired() {
        var el = $("hidComplexity");
        return !!el && el.value === "1";
    }

    /* Число категорий символов, присутствующих в пароле (0..4). */
    function countCategories(value) {
        var n = 0;
        if (/[A-ZА-ЯЁ]/.test(value)) { n++; }
        if (/[a-zа-яё]/.test(value)) { n++; }
        if (/[0-9]/.test(value)) { n++; }
        if (/[\W_]/.test(value)) { n++; }
        return n;
    }

    /* Соответствует ли пароль политике (длина + сложность). */
    function isNewPasswordValid(value) {
        if (!value) {
            return false;
        }

        var minLength = getMinLength();
        if (minLength > 0 && value.length < minLength) {
            return false;
        }

        if (getComplexityRequired() && countCategories(value) < 3) {
            return false;
        }

        return true;
    }

    /* ----------------------------------------------------------
     * 3. Динамическая проверка нового пароля (шкала + чек-лист)
     * ---------------------------------------------------------- */

    function checkPassword(value) {
        var minLength = getMinLength();
        var complex = getComplexityRequired();

        return {
            length: !minLength || value.length >= minLength,
            upper: /[A-ZА-ЯЁ]/.test(value),
            lower: /[a-zа-яё]/.test(value),
            digit: /[0-9]/.test(value),
            special: /[\W_]/.test(value),
            complex: !complex || countCategories(value) >= 3
        };
    }

    function countPassed(checks) {
        var keys = ["length", "complex"];
        var n = 0;
        var i;

        for (i = 0; i < keys.length; i++) {
            if (checks[keys[i]]) {
                n++;
            }
        }

        return n;
    }

    function totalChecks() {
        var total = 0;
        if (getMinLength() > 0) { total++; }
        if (getComplexityRequired()) { total++; }
        return total;
    }

    function updateMeter(passed, total) {
        var bar = $("pwdMeterBar");

        if (!bar) {
            return;
        }

        if (total === 0) {
            bar.style.width = "0%";
            return;
        }

        var pct = (passed / total) * 100;

        bar.style.width = pct + "%";

        if (pct >= 100) {
            bar.style.backgroundColor = "#2e7d32";
        } else if (pct >= 50) {
            bar.style.backgroundColor = "#ef6c00";
        } else {
            bar.style.backgroundColor = "#c62828";
        }
    }

    function updateCheckList(value, checks) {
        var list = $("pwdChecks");
        var complex = getComplexityRequired();

        if (!list) {
            return;
        }

        var items = list.querySelectorAll("li");
        var i;

        for (i = 0; i < items.length; i++) {
            var li = items[i];
            var kind = li.getAttribute("data-check");
            var ok = false;

            if (kind === "length") {
                ok = checks.length;
            } else if (complex) {
                /* Отдельные категории показываем только при сложности */
                ok = checks[kind];
            } else {
                /* Сложность не требуется — скрываем категории */
                li.style.display = "none";
                continue;
            }

            li.style.display = "";

            if (ok) {
                li.classList.add("ok");
            } else {
                li.classList.remove("ok");
            }
        }
    }

    function refreshPasswordMeter() {
        var input = $("txtNewPassword");
        var req = $("pwdRequirements");

        if (!input || !req) {
            return;
        }

        var value = input.value;
        var total = totalChecks();

        if (value.length === 0 || total === 0) {
            req.style.display = "none";
            return;
        }

        req.style.display = "block";

        var checks = checkPassword(value);
        var passed = countPassed(checks);

        updateMeter(passed, total);
        updateCheckList(value, checks);
    }

    /* ----------------------------------------------------------
     * 4. Проверка совпадения повтора пароля
     * ---------------------------------------------------------- */

    function refreshConfirmState() {
        var newInput = $("txtNewPassword");
        var confirmInput = $("txtConfirmPassword");
        var mismatch = $("pwdMismatch");

        if (!newInput || !confirmInput) {
            return;
        }

        var confirmValue = confirmInput.value;

        /* Пока поле подтверждения пустое — ошибку не показываем. */
        if (confirmValue.length === 0) {
            if (mismatch) { mismatch.style.display = "none"; }
            confirmInput.classList.remove("input-error");
            return;
        }

        var match = (confirmValue === newInput.value);

        if (match) {
            if (mismatch) { mismatch.style.display = "none"; }
            confirmInput.classList.remove("input-error");
        } else {
            if (mismatch) { mismatch.style.display = "block"; }
            confirmInput.classList.add("input-error");
        }
    }

    /* ----------------------------------------------------------
     * 5. Блокировка кнопки до корректного заполнения
     * ---------------------------------------------------------- */

    function captchaVisibleAndRequired() {
        var input = $("txtCaptcha");
        return !!input && input.offsetParent !== null;
    }

    function validateForm() {
        var btn = $("btnChange");
        if (!btn) {
            return;
        }

        var username = $("txtUsername");
        var current = $("txtCurrentPassword");
        var newInput = $("txtNewPassword");
        var confirm = $("txtConfirmPassword");

        var ok = true;

        if (!username || username.value.trim().length === 0) { ok = false; }
        if (!current || current.value.length === 0) { ok = false; }
        if (!newInput || !isNewPasswordValid(newInput.value)) { ok = false; }
        if (!confirm || confirm.value.length === 0 || confirm.value !== newInput.value) { ok = false; }
        if (captchaVisibleAndRequired()) {
            var captcha = $("txtCaptcha");
            if (!captcha || captcha.value.trim().length === 0) { ok = false; }
        }

        btn.disabled = !ok;
    }

    /* ----------------------------------------------------------
     * 6. Инициализация
     * ---------------------------------------------------------- */

    function initPasswordCheck() {
        var newInput = $("txtNewPassword");
        var confirm = $("txtConfirmPassword");

        if (newInput) {
            newInput.addEventListener("input", refreshPasswordMeter);
            newInput.addEventListener("input", refreshConfirmState);
            newInput.addEventListener("input", validateForm);
        }

        if (confirm) {
            confirm.addEventListener("input", refreshConfirmState);
            confirm.addEventListener("input", validateForm);
        }

        var username = $("txtUsername");
        if (username) {
            username.addEventListener("input", validateForm);
        }

        var current = $("txtCurrentPassword");
        if (current) {
            current.addEventListener("input", validateForm);
        }

        var captcha = $("txtCaptcha");
        if (captcha) {
            captcha.addEventListener("input", validateForm);
        }

        /* Начальное состояние: сброс и блокировка кнопки. */
        refreshPasswordMeter();
        refreshConfirmState();
        validateForm();
    }

    /* ----------------------------------------------------------
     * Запуск после загрузки DOM (скрипт подключён с defer)
     * ---------------------------------------------------------- */

    initEyeToggles();
    initPasswordCheck();
})();
