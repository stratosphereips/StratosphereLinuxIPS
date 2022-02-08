let profiles = function(){
    let table = $('#profiles').DataTable({
            ajax: '/profiles_tws',
            serverSide: true,
            "scrollY":        "700px",
            "scrollCollapse": true,
            "paging":         false,
            "bInfo" : false,
            ordering: false,
            searching: false,
            "rowId": 'id',
            columns: [
              {
                    "className":      'dt-control',
                    "orderable":      false,
                    "data":           null,
                    "defaultContent": ''
                },
              {data: 'profile',
              "className": 'r'}

            ],
            "order": [[1, 'asc']]
            });
    return{
        onclick_tws: function(){
            function add_tws(profile_tws) {
                const open_string = '<table class="table table-striped">'
                const close_string = '</table>'
                let data = ""
                profile_tws.tws.forEach(item => {
                data = data + '<tr onclick="hotkey_hook.initialize_profile_timewindow(' + "'" + "profile_" + profile_tws.profile+"'" + ',' + "'" + item + "'" +')">' + '<td>'+ item + '</td>' + '</tr>';})
                return open_string + data + close_string;
            }

            $('#profiles').on('click', 'tbody td.dt-control', function () {
                let tr = $(this).closest('tr');
                let row = table.row( tr );
                if (row.child.isShown()) {
                    row.child.hide();
                }
                else {
                    row.child(add_tws(row.data())).show();
                }
            });
        },

        onclick_ips: function(){
            $('#profiles ').on( 'click', 'tbody td.r', function () {
                let data = table.row( $(this).parents('tr')).data();
                let url = '/info/' + data.profile
                ipinfo.ajax.url(url).load();
            });
        }
    }
}
let profile = profiles();
profile.onclick_tws();
profile.onclick_ips();


let operate_hotkeys = function(){

    let profile = '';
    let timewindow = '';
    let active_hotkey = 'timeline';
    let last_active_hotkey = 'timeline';

            "bDestroy": true,
            columns: [
              {data: 'ts'},
              {data: 'dur'},
              {data: 'saddr'},
              {data: 'sport'},
              {data: 'daddr'},
              {data: 'dport'},
              {data: 'proto'},
              {data: 'origstate'},
              {data: 'state'},
              {data: 'pkts'},
              {data: 'allbytes'},
              {data: 'spkts'},
              {data: 'sbytes'}
            ]
});
        update_timeline_flows: function(){
            let link = '/timeline_flows/' + profile + '/' + timewindow;
            timeline_flows.ajax.url(link).load();
            x = document.getElementById("timeline_flows");
            x.style.display = "block"
            },

let timewindows = {
    'update_timeline': function (profile, timewindow) {
        let s = '/timeline/' + profile + '/' + timewindow
        datatable.ajax.url(s).load();
        update_timeline: function(){
            let s = '/timeline/' + profile + '/' + timewindow;
            timeline.ajax.url(s).load();
            x = document.getElementById("timeline");
            x.style.display = "block"
            },
    }
}

let ipinfo = $('#ipinfo').DataTable({
            "bDestroy": true,
            ordering:   false,
            searching:  false,
            "paging":   false,
            "bInfo" :   false,
            columns: [
              {data: 'ip'},
              {data: 'geocountry'},
              {data: 'reverse_dns'},
              {data: 'asnorg'}
            ]
});


