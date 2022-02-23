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

    let timeline_flows = $('#table_timeline_flows').DataTable({
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

    let timeline = $('#table_timeline').DataTable({
            "bDestroy": true,
            columns: [
              {data: 'timestamp'},
              {data: 'dport_name'},
              {data: 'preposition'},
//              {data: 'dns_resolution'},
//              {data: 'dport/proto'},
              {data: 'daddr'}
//              {data: 'info'}
            ]
    });

    let outtuples = $('#table_outtuples').DataTable({
        "bDestroy": true,
        columns: [
          {data: 'tuple'},
          {data: 'string'},
//          {data: 'preposition'},
//              {data: 'dns_resolution'},
//              {data: 'dport/proto'},
//          {data: 'daddr'}
//              {data: 'info'}
        ]
    });

    function hide_hotkey(){
        x = document.getElementById(last_active_hotkey);
        x.style.display = "none"
        last_active_hotkey = active_hotkey;
    }

    return{
        set_profile_timewindow: function(pr, tw){
            profile = pr;
            timewindow = tw;
            },

        get_active_hotkey: function(){
            return active_hotkey;
        },

        update_timeline_flows: function(){
            let link = '/timeline_flows/' + profile + '/' + timewindow;
            timeline_flows.ajax.url(link).load();
            x = document.getElementById("timeline_flows");
            x.style.display = "block"
            },

        update_timeline: function(){
            let s = '/timeline/' + profile + '/' + timewindow;
            timeline.ajax.url(s).load();
            x = document.getElementById("timeline");
            x.style.display = "block"
            },

        onclick_buttons: function(){
            $("#buttons .btn").click(function(){
                $("#buttons .btn").removeClass('active');
                $(this).toggleClass('active');
                let [first, ...rest] = (this.id).split('_');
                active_hotkey = rest.join('_');
                if(active_hotkey != last_active_hotkey){
                    hide_hotkey();}
                });
            }
    }
}
2

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

let hotkeys = operate_hotkeys();
hotkeys.onclick_buttons();

let hotkey_hook = {
    'initialize_profile_timewindow': function(profile, timewindow){
        hotkeys.set_profile_timewindow(profile, timewindow);
        hotkey_hook.initialize_hotkey();
    },
    'initialize_hotkey':function(){
        let active_hotkey = hotkeys.get_active_hotkey();
        if(active_hotkey == 'timeline'){
            hotkey_hook.set_timeline();
        }
        else if(active_hotkey == 'timeline_flows'){
            hotkey_hook.set_timeline_flows();
        }

    },
    'set_timeline_flows': function(){
        hotkeys.update_timeline_flows();
    },

    'set_timeline': function(){
        hotkeys.update_timeline();
    }
}



