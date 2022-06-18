let table = $('#general_blockedProfilesTWs').DataTable({
    ajax: '/general/blockedProfileTWs',
    "bDestroy": true,
    ordering: false,
    searching: false,
    "paging": false,
    "bInfo": false,
    columns: [{ data: 'blocked' }]
});