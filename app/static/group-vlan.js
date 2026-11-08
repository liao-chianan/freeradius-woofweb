(function () {
    'use strict';
    // AD 群組的額外 VLAN：排在上面的優先，用 ↑ ↓ 移動整列（送出的順序就是表格的順序）
    var table = document.querySelector('.group-vlan-table tbody');
    if (!table) { return; }
    Array.prototype.forEach.call(table.querySelectorAll('.js-vlan-up, .js-vlan-down'), function (button) { button.hidden = false; });
    table.addEventListener('click', function (event) {
        var button = event.target.closest('.js-vlan-up, .js-vlan-down');
        if (!button) { return; }
        var row = button.closest('tr');
        if (button.classList.contains('js-vlan-up') && row.previousElementSibling) {
            table.insertBefore(row, row.previousElementSibling);
        } else if (button.classList.contains('js-vlan-down') && row.nextElementSibling) {
            table.insertBefore(row.nextElementSibling, row);
        }
        button.focus();
    });
})();
