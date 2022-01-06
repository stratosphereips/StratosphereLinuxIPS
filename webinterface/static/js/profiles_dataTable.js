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
              {data: 'profile'},
              {
                "targets": -1,
                "data": null,
                "defaultContent":'<button type="button" class="btn btn-primary" data-toggle="modal">Info</button>' // data-target="#exampleModalCenter"
                }
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
                data = data + '<tr onclick="timewindows.update_timeline(' + "'" + profile_tws.profile+"'" + ',' + "'" + item + "'" +')">' + '<td>'+ item + '</td>' + '</tr>';})
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

        onclick_buttons: function(){
            $('#profiles ').on( 'click', 'tbody button', function () {
                let data = table.row( $(this).parents('tr')).data();
                let profile_IP = data.profile.split("_")[1]
                let url = '/info/' + profile_IP
                ipinfo.ajax.url(url).load();
            });
        }
    }
}
let profile = profiles();
profile.onclick_tws();
profile.onclick_buttons();

let datatable = $('#timeline').DataTable({
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

let timewindows = {
    'update_timeline': function (profile, timewindow) {
        let s = '/timeline/' + profile + '/' + timewindow
        datatable.ajax.url(s).load();
    }
}

let ipinfo = $('#ipinfo').DataTable({
            "bDestroy": true,
            ordering:   false,
            searching:  false,
            "paging":   false,
            "bInfo" :   false,
            columns: [
              {data: 'field'},
              {data: 'value'}

            ]
});


