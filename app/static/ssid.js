(function () {
    'use strict';
    // 管理介面掛在 /woofradius 之類的前綴底下，由 base.html 的 body data-base 提供
    var BASE = document.body.dataset.base || '';
    // 儲存前先向伺服器要更動範圍，顯示在確認視窗；確認後送出 confirmed=1 直接儲存。
    // 沒有 JavaScript 時表單照舊送到 /ssid，改用確認頁。
    var form = document.getElementById('ssid-form');
    var dialog = document.getElementById('ssid-confirm');
    if (!form || !dialog || typeof dialog.showModal !== 'function') { return; }
    var busy = false;

    function cell(row, text, className) {
        var td = document.createElement('td');
        td.textContent = text;
        if (className) { td.className = className; }
        row.appendChild(td);
    }

    function showError(message) {
        var box = document.querySelector('.ssid-js-error');
        if (!box) {
            box = document.createElement('div');
            box.className = 'notice error ssid-js-error';
            box.setAttribute('role', 'alert');
            form.parentNode.insertBefore(box, form);
        }
        box.textContent = message;
        box.scrollIntoView({ block: 'center' });
    }

    function showInfo(message) {
        var old = document.querySelector('.ssid-js-error');
        if (old) { old.remove(); }
        var box = document.createElement('div');
        box.className = 'notice success ssid-js-error';
        box.setAttribute('role', 'status');
        box.textContent = message;
        form.parentNode.insertBefore(box, form);
        box.scrollIntoView({ block: 'center' });
    }

    form.addEventListener('submit', function (event) {
        event.preventDefault();
        if (busy) { return; }
        busy = true;
        fetch(BASE + '/ssid/preview', { method: 'POST', body: new FormData(form), credentials: 'same-origin' })
            .then(function (res) {
                if (!res.ok) { throw new Error('HTTP ' + res.status); }
                return res.json();
            })
            .then(function (data) {
                if (!data.ok) { showError(data.error || '規則有誤，未儲存'); return; }
                if (data.unchanged) { showInfo('規則沒有變更'); return; }
                var old = document.querySelector('.ssid-js-error');
                if (old) { old.remove(); }
                var list = document.getElementById('ssid-confirm-changes');
                list.textContent = '';
                data.changes.forEach(function (change) {
                    var li = document.createElement('li');
                    var tag = document.createElement('b');
                    tag.textContent = change.kind + '：';
                    li.appendChild(tag);
                    li.appendChild(document.createTextNode(change.text));
                    list.appendChild(li);
                });
                var body = document.getElementById('ssid-confirm-impact');
                body.textContent = '';
                var warned = false;
                data.impact.forEach(function (item) {
                    var tr = document.createElement('tr');
                    cell(tr, item.ssid, 'strong');
                    cell(tr, item.before);
                    cell(tr, item.after);
                    cell(tr, item.warning, item.warning ? 'status-off' : '');
                    if (item.warning) { warned = true; }
                    body.appendChild(tr);
                });
                document.getElementById('ssid-confirm-impact-wrap').hidden = !data.impact.length;
                document.getElementById('ssid-confirm-none').hidden = !!data.impact.length;
                document.getElementById('ssid-confirm-unaffected').textContent =
                    data.impact.length && data.unaffected ? '另有 ' + data.unaffected + ' 個 SSID 不受影響。' : '';
                document.getElementById('ssid-confirm-warn').hidden = !warned;
                document.getElementById('ssid-confirm-proxy').hidden = !data.proxy_missing;
                document.getElementById('ssid-confirm-json').value = data.rules_json;
                dialog.showModal();
            })
            .catch(function (err) { showError('無法取得更動範圍（' + err.message + '），規則未儲存'); })
            .then(function () { busy = false; });
    });

    document.getElementById('ssid-confirm-cancel').addEventListener('click', function () { dialog.close(); });
}());
