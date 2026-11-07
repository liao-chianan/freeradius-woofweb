(function () {
    'use strict';
    var BASE = document.body.dataset.base || '';
    var $ = function (id) { return document.getElementById(id); };

    function show(text, kind) {
        var el = $('bench-message');
        el.hidden = false;
        el.className = 'notice ' + (kind || 'success');
        el.textContent = text;
    }

    var polling = false;
    function poll() {
        if (polling) { return; }
        polling = true;
        $('bench-progress').hidden = false;
        $('bench-button').disabled = true;
        (function tick() {
            fetch(BASE + '/settings/performance/status', { credentials: 'same-origin' }).then(function (res) {
                if ((res.headers.get('Content-Type') || '').indexOf('application/json') === -1) { throw new Error('連線逾時或已登出，請重新整理'); }
                return res.json();
            }).then(function (data) {
                if (data.state === 'running') {
                    $('bench-phase').textContent = data.phase || '準備中';
                    setTimeout(tick, 2000);
                    return;
                }
                location.reload();
            }).catch(function (err) {
                show(err.message, 'error');
                setTimeout(tick, 5000);
            });
        })();
    }

    $('bench-button').addEventListener('click', function () {
        $('password-form').reset();
        $('password-dialog').showModal();
    });
    $('password-cancel').addEventListener('click', function () { $('password-dialog').close(); });
    $('password-form').addEventListener('submit', function (event) {
        event.preventDefault();
        var data = new FormData();
        data.append('password', $('password-form').password.value);
        $('password-dialog').close();
        $('bench-button').disabled = true;
        fetch(BASE + '/settings/performance/start', { method: 'POST', body: data, credentials: 'same-origin' }).then(function (res) {
            if ((res.headers.get('Content-Type') || '').indexOf('application/json') === -1) { throw new Error('連線逾時或已登出，請重新整理（HTTP ' + res.status + '）'); }
            return res.json();
        }).then(function (result) {
            if (!result.ok) { show(result.error || '無法開始', 'error'); $('bench-button').disabled = false; return; }
            poll();
        }).catch(function (err) { show(err.message, 'error'); $('bench-button').disabled = false; });
    });

    if (!$('bench-progress').hidden) { poll(); }
})();
