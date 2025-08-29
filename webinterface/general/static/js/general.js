// SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
//SPDX-License-Identifier: GPL-2.0-only
let table = $('#general_blockedProfilesTWs').DataTable({
    ajax: '/general/blockedProfileTWs',
    "bDestroy": true,
    ordering: false,
    searching: false,
    "paging": false,
    "bInfo": false,
    columns: [{ data: 'blocked' }]
});
