(function () {
    'use strict';
    // Google、Proxy 帳號的登入紀錄對話框（與 AD 帳號頁相同的欄位）。點帳號開啟。
    var BASE = document.body.dataset.base || '';
    var box = document.getElementById('logins-dialog');
    if (!box) { return; }
    var $ = function (id) { return document.getElementById(id); };
    var COLUMNS = [{ title: '登入時間', key: 'time', className: 'nowrap' },
                   { title: '連線 AP', key: 'ap_name', className: 'nowrap' },
                   { title: '要求認證的 IP', key: 'ip', className: 'mono' },
                   { title: '裝置 MAC', key: 'mac', className: 'mono' },
                   { title: 'AP MAC', key: 'ap_mac', className: 'mono' },
                   { title: 'SSID', key: 'ssid' }];

    function cell(row, tag, text, className) {
        var c = document.createElement(tag);
        c.textContent = text;
        if (className) { c.className = className; }
        row.appendChild(c);
    }

    function failed(text) {
        $('logins-error').textContent = text;
        $('logins-error').hidden = false;
        $('logins-note').textContent = '';
    }

    function show(label, url) {
        var body = $('logins-rows');
        var head = $('logins-head');
        $('logins-device').textContent = label;
        head.textContent = '';
        var headRow = head.insertRow();
        COLUMNS.forEach(function (column) { cell(headRow, 'th', column.title); });
        body.textContent = '';
        $('logins-note').textContent = '讀取中…';
        $('logins-error').hidden = true;
        $('logins-empty').hidden = true;
        $('logins-wrap').hidden = true;
        box.showModal();
        fetch(url, { credentials: 'same-origin' }).then(function (res) {
            var type = res.headers.get('content-type') || '';
            if (res.redirected || type.indexOf('application/json') === -1) {
                location.href = BASE + '/login';
                throw new Error('login required');
            }
            return res.json();
        }).then(function (data) {
            if (!data.ok) { failed(data.errors.join('、')); return; }
            data.rows.forEach(function (item) {
                var tr = body.insertRow();
                COLUMNS.forEach(function (column) { cell(tr, 'td', item[column.key] || '未記錄', column.className); });
            });
            $('logins-wrap').hidden = data.rows.length === 0;
            $('logins-empty').hidden = data.rows.length !== 0;
            $('logins-note').textContent = '共 ' + data.rows.length + ' 筆；每個帳號保留最近 ' + data.retention + ' 筆，可到系統設定變更。';
        }).catch(function (err) {
            if (err.message !== 'login required') { failed('讀取失敗，請稍後再試'); }
        });
    }

    box.querySelectorAll('.js-close').forEach(function (button) {
        button.addEventListener('click', function () { box.close(); });
    });
    document.addEventListener('click', function (event) {
        var button = event.target.closest('.js-account-logins');
        if (button) { show(button.dataset.label, button.dataset.url); }
    });
}());
