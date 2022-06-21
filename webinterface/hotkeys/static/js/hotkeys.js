
 let operate_hotkeys = function () {
    let profile = '';
    let timewindow = '';
    let active_hotkey_name = 'timeline';
    let last_active_hotkey_name = 'timeline';
    let active_hotkey_table = null

    let timeline_flows = $('#table_timeline_flows').DataTable({
        'dom': 'Rlfrtip',
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
                'dom': 'Rlfrtip',
        columns: [
            { data: 'timestamp' },
            { data: 'dport_name' },
            { data: 'dns_resolution' },
            { data: 'daddr' },
            { data: 'preposition' },
            { data: 'dport/proto' },
            { data: 'state' },
            { data: 'warning' },
            { data: 'Sent' },
            { data: 'Recv' },
            { data: 'Tot' },
            { data: 'Duration' },
            { data: 'critical warning' },
            { data: 'info' }
        ]
    });

    let outtuples = $('#table_outtuples').DataTable({
        "bDestroy": true,
        'dom': 'Rlfrtip',
        columns: [
            { data: 'tuple' },
            { data: 'string' },
            { data: 'geocountry' },
            { data: 'reverse_dns' },
            { data: 'asnorg' }
        ]
    });

    let alerts = $('#table_alerts').DataTable({
        "bDestroy": true,
        'dom': 'Rlfrtip',
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
        let link = "/hotkeys/" + active_hotkey_name + "/" + profile + "/" + timewindow
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
                let url = '/hotkeys/info/' + data.saddr
                ipinfo.ajax.url(url).load();
            })
        },

        onclick_timeline_flows_daddr: function () {
        $('#table_timeline_flows ').on('click', 'tbody td.daddr', function () {
                let data = timeline_flows.row($(this).parents('tr')).data();
                let url = '/hotkeys/info/' + data.daddr
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


// BAR CHART EXAMPLE
//const headers = {
//    headers: {'Content-Type': 'application/json'}
//}
//fetch("/hotkeys/dstIP", {
//        method: "GET",
//        headers: headers
//        }).then(response => response.json())
//        .then(data => {
//                        const x = data['data'].map(function(d){ return d['ip']})
//                        const y = data['data'].map(function(d){ return d['flow']})
//                        const chart_data = {
//                            labels: x,
//                            datasets: [{
//                            label: 'Monthly Sales',
//                            backgroundColor: 'rgb(255, 99, 132)',
//                            borderColor: 'rgb(255, 99, 132)',
//                            data: y,
//                            }]
//                        };
//                        const config = {
//                            type: 'bar',
//                            data: chart_data,
//                            options: {}
//                        };
//                        const monthlySales = new Chart(
//                            document.getElementById('barchart'),
//                            config
//                        );
//
//                    });

