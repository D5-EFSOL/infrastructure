/* ============================================================
 * SelfPortal — клиентская логика (глазок + динамическая проверка)
 *
 * Вся логика вынесена во внешний файл, т.к. CSP запрещает
 * inline-скрипты (script-src 'self').
 *
 * Работает с серверными полями (ClientID без префиксов, т.к.
 * Panel не является naming container):
 *   txtCurrentPassword, txtNewPassword, txtConfirmPassword,
 *   hidMinLength, hidComplexity
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
     * 2. Динамическая проверка нового пароля
     * ----------------------------------------------------------
     *
     * Проверяем только то, что реально задано политикой:
     *   - минимальную длину (hidMinLength > 0);
     *   - сложность (hidComplexity == "1") — три из четырёх
     *     категорий, как требует Windows.
     * ---------------------------------------------------------- */

    function getMinLength() {
        var el = $("hidMinLength");
        var v = el ? parseInt(el.value, 10) : 0;
        return isNaN(v) ? 0 : v;
    }

    function getComplexityRequired() {
        var el = $("hidComplexity");
        return el && el.value === "1";
    }

    function checkPassword(value) {
        var minLength = getMinLength();
        var complex = getComplexityRequired();

        var checks = {
            length: !minLength || value.length >= minLength,
            upper: !complex || /[A-ZА-ЯЁ]/.test(value),
            lower: !complex || /[a-zа-яё]/.test(value),
            digit: !complex || /[0-9]/.test(value),
            special: !complex || /[\W_]/.test(value)
        };

        /* Для сложности Windows достаточно 3 категорий из 4. */
        var categories = 0;
        if (/[A-ZА-ЯЁ]/.test(value)) { categories++; }
        if (/[a-zа-яё]/.test(value)) { categories++; }
        if (/[0-9]/.test(value)) { categories++; }
        if (/[\W_]/.test(value)) { categories++; }

        checks.complex = !complex || categories >= 3;

        return checks;
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
            } else if (kind === "complex") {
                ok = checks.complex;
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

    function onNewPasswordInput() {
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

    function initPasswordCheck() {
        var input = $("txtNewPassword");

        if (!input) {
            return;
        }

        input.addEventListener("input", onNewPasswordInput);
    }

    /* ----------------------------------------------------------
     * Инициализация после загрузки DOM (скрипт подключён с defer)
     * ---------------------------------------------------------- */

    initEyeToggles();
    initPasswordCheck();
})();
