/*
Set profile and timewindow table.
Functions:
    onclick_tws:
    onclick_ips: display a list of timewindows onclick, and the IP info
*/
let profiles = function () {
    let profiles_table = $('#profiles').DataTable({
        ajax: '/hotkeys/profiles_tws',
        serverSide: true,
        "scrollY":  true,
        "scrollCollapse": true,
        "paging": false,
        "bInfo": false,
        ordering: false,
        searching: false,
        "rowId": 'id',
        columns: [
            {
                "className": 'dt-control',
                "orderable": false,
                "data": null,
                "defaultContent": ''
            },
            {
                data: 'profile',
                "className": 'r'
            }

        ],
        "order": [[1, 'asc']]
    });
    return {
        onclick_tws: function () {
            function add_tws(profile_tws) {
                const open_string = '<table class="table table-striped">'
                const close_string = '</table>'
                let data = ""
                profile_tws.tws.forEach(item => {
                    data = data + '<tr onclick="hotkey_hook.initialize_profile_timewindow(' + "'" + "profile_" + profile_tws.profile + "'" + ',' + "'" + item + "'" + ')">' + '<td>' + item + '</td>' + '</tr>';
                })
                return open_string + data + close_string;
            }

            $('#profiles').on('click', 'tbody td.dt-control', function () {
                let tr = $(this).closest('tr');
                let row = profiles_table.row(tr);
                if (row.child.isShown()) {
                    row.child.hide();
                }
                else {
                    row.child(add_tws(row.data())).show();
                }
            });
        },

        onclick_ips: function () {
            $('#profiles ').on('click', 'tbody td.r', function () {
                let data = profiles_table.row($(this).parents('tr')).data();
                let url = '/info/' + data.profile
                hotkeys.ipinfo.ajax.url(url).load();
            });
        }
    }
}

let profile = profiles();
profile.onclick_tws();
profile.onclick_ips();