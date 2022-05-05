/*
Set profile and timewindow table.
Functions:
    onclick_tws:
    onclick_ips: display a list of timewindows onclick, and the IP info
*/
let profiles = function () {
    let profiles_table = $('#profiles').DataTable({
        ajax: '/profiles_tws',
        serverSide: true,
        "scrollY": "700px",
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
                ipinfo.ajax.url(url).load();
            });
        }
    }
}

 let operate_hotkeys = function () {
    let profile = '';
    let timewindow = '';
    let active_hotkey_name = 'timeline';
    let last_active_hotkey_name = 'timeline';
    let active_hotkey_table = null

    let timeline_flows = $('#table_timeline_flows').DataTable({
        "bDestroy": true,
        columns: [
            { data: 'ts' },
            { data: 'dur' },
            { data: 'saddr' ,
              "className": 'saddr'},
            { data: 'sport' },
            { data: 'daddr' ,
            "className": 'daddr'},
            { data: 'dport' },
            { data: 'proto' },
            { data: 'origstate' },
            { data: 'state' },
            { data: 'pkts' },
            { data: 'allbytes' },
            { data: 'spkts' },
            { data: 'sbytes' }
        ]
    });

    let timeline = $('#table_timeline').DataTable({
        "bDestroy": true,
        columns: [
            { data: 'timestamp' },
            { data: 'dport_name' },
            { data: 'preposition' },
            { data: 'daddr' }
        ]
    });

    let outtuples = $('#table_outtuples').DataTable({
        "bDestroy": true,
        columns: [
            { data: 'tuple' },
            { data: 'string'}
        ]
    });

    let alerts = $('#table_alerts').DataTable({
        "bDestroy": true,
        columns: [
            { data: 'profileid' },
            { data: 'twid'},
            { data: 'type_detection' },
            { data: 'detection_info'},
            { data: 'type_evidence' },
            { data: 'description'},
            { data: 'stime'},
            { data: 'uid' },
            { data: 'confidence'},
            { data: 'threat_level'},
            { data: 'category' }
        ]
    });

    function hide_hotkey() {
        document.getElementById(last_active_hotkey_name).style.display = "none"
        last_active_hotkey_name = active_hotkey_name;
    }

    function update_table(){
        switch (active_hotkey_name) {
            case 'timeline':
                active_hotkey_table = timeline
                break;
            case 'timeline_flows':
                active_hotkey_table = timeline_flows
                break;
            case 'outtuples':
                active_hotkey_table = outtuples
                break;
            case 'alerts':
                active_hotkey_table = alerts
                break;
        }
        let link = "/" + active_hotkey_name + "/" + profile + "/" + timewindow
        active_hotkey_table.ajax.url(link).load();
        document.getElementById(active_hotkey_name).style.display = "block"
    }

    return {

        set_profile_timewindow: function (pr, tw) {
            profile = pr;
            timewindow = tw;
        },

        update_table_hook: function(){
            update_table()
        },

        onclick_buttons: function () {
            $("#buttons .btn").click(function () {
                $("#buttons .btn").removeClass('active');
                $(this).toggleClass('active');
                let [first, ...rest] = (this.id).split('_');
                active_hotkey_name = rest.join('_');
                if (active_hotkey_name != last_active_hotkey_name) {
                    hide_hotkey();
                }
               update_table()
            });
        },

        onclick_timeline_flows_saddr: function () {
        $('#table_timeline_flows ').on('click', 'tbody td.saddr', function () {
                let data = timeline_flows.row($(this).parents('tr')).data();
                let url = '/info/' + data.saddr
                ipinfo.ajax.url(url).load();
            })
        },
        onclick_timeline_flows_daddr: function () {
        $('#table_timeline_flows ').on('click', 'tbody td.daddr', function () {
                let data = timeline_flows.row($(this).parents('tr')).data();
                let url = '/info/' + data.daddr
                ipinfo.ajax.url(url).load();
            })
        }
    }
}

let ipinfo = $('#ipinfo').DataTable({
    "bDestroy": true,
    ordering: false,
    searching: false,
    "paging": false,
    "bInfo": false,
    columns: [
        { data: 'ip' },
        { data: 'geocountry' },
        { data: 'reverse_dns' },
        { data: 'asnorg' }
    ]
});

let hotkeys = operate_hotkeys();
hotkeys.onclick_buttons();
hotkeys.onclick_timeline_flows_saddr();
hotkeys.onclick_timeline_flows_daddr();

let hotkey_hook = {
    'initialize_profile_timewindow': function (profile, timewindow) {
        hotkeys.set_profile_timewindow(profile, timewindow);
        hotkeys.update_table_hook();
    }
}

