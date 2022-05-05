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

let profile = profiles();
profile.onclick_tws();
profile.onclick_ips();


let operate_hotkeys = function () {

    let profile = '';
    let timewindow = '';
    let active_hotkey = 'timeline';
    let last_active_hotkey = 'timeline';

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

//"{\"domain 0.debian.pool.ntp.org resolved with no connection\": \"{\\\"profileid\\\": \\\"profile_192.168.2.16\\\",
//\\\"twid\\\": \\\"timewindow1\\\", \\\"type_detection\\\": \\\"dstdomain\\\", \\\"detection_info\\\": \\\"0.debian.pool.ntp.org\\\",
//\\\"type_evidence\\\": \\\"DNSWithoutConnection\\\", \\\"description\\\": \\\"domain 0.debian.pool.ntp.org resolved with no connection\\\",
//\\\"stime\\\": 1520628615.698819, \\\"uid\\\": \\\"CXSJnM1kDZ5tjRt2Sk\\\", \\\"confidence\\\": 0.8, \\\"threat_level\\\": \\\"low\\\", \\\"category\\\": \\\"Anomaly.Traffic\\\"}\",
    function hide_hotkey() {
        x = document.getElementById(last_active_hotkey);
        x.style.display = "none"
        last_active_hotkey = active_hotkey;
    }

    return {

        set_profile_timewindow: function (pr, tw) {
            profile = pr;
            timewindow = tw;
        },

        get_active_hotkey: function () {
            return active_hotkey;
        },

        update_timeline_flows: function () {
            let link = '/timeline_flows/' + profile + '/' + timewindow;
            timeline_flows.ajax.url(link).load();
            x = document.getElementById("timeline_flows");
            x.style.display = "block"
        },

        update_timeline: function () {
            let link = '/timeline/' + profile + '/' + timewindow;
            timeline.ajax.url(link).load();
            x = document.getElementById("timeline");
            x.style.display = "block"
        },

        update_outtuples: function () {
            let link = '/outtuples/' + profile + '/' + timewindow;
            outtuples.ajax.url(link).load();
            x = document.getElementById("outtuples");
            x.style.display = "block"
        },

        update_alerts: function () {
            let link = '/alerts/' + profile + '/' + timewindow;
            alerts.ajax.url(link).load();
            x = document.getElementById("alerts");
            x.style.display = "block"
        },

        onclick_buttons: function () {
            $("#buttons .btn").click(function () {
                $("#buttons .btn").removeClass('active');
                $(this).toggleClass('active');
                let [first, ...rest] = (this.id).split('_');
                active_hotkey = rest.join('_');
                if (active_hotkey != last_active_hotkey) {
                    hide_hotkey();
                }
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
        hotkey_hook.initialize_hotkey();
    },
    'initialize_hotkey': function () {
        let active_hotkey = hotkeys.get_active_hotkey();
        if (active_hotkey == 'timeline') {
            hotkey_hook.set_timeline();
        }
        else if (active_hotkey == 'timeline_flows') {
            hotkey_hook.set_timeline_flows();
        }
        else if (active_hotkey == 'outtuples') {
            hotkey_hook.set_timewindow_outtuples();
        }
        else if (active_hotkey == 'alerts') {
            hotkey_hook.set_alerts();
        }
    },
    'set_timeline_flows': function () {
        hotkeys.update_timeline_flows();
    },
    'set_timeline': function () {
        hotkeys.update_timeline();
    },
    'set_alerts': function(){
        hotkeys.update_alerts();
    },
    'set_timewindow_outtuples': function () {
        hotkeys.update_outtuples();
    }
}



