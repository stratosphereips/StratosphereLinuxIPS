function format ( d ) {
    const open_string = '<table cellpadding="5" cellspacing="0" border="0" style="padding-left:50px;">'
    const close_string = '</table>'
    let data = ""
    d.tws.forEach(item=> data = data + '<tr>'+ '<td>'+ item + '</td>'+ '</tr>')
    return open_string + data + close_string;
    }

$(document).ready(function () {
    $('#profiles').on('click', 'tbody td.dt-control', function () {
            var tr = $(this).closest('tr');
            var row = table.row( tr );

            if ( row.child.isShown() ) {
                // This row is already open - close it
                row.child.hide();
            }
            else {
                // Open this row
                row.child( format(row.data())).show();
            }
          });

    $('#profiles').on('requestChild.dt', function(e, row) {
        row.child(format(row.data())).show();
    })

$('#profiles ').on( 'click', ' tbody button', function () {
        let data = table.row( $(this).parents('tr')).data();
        let profile_IP = data.profile.split("_")[1]
        let url = '/info/' + profile_IP

        $.getJSON(url, data => {
              //do nothing
              var modal = $('#exampleModalCenter')
              modal.find('.modal-body').text(data.asn.asnorg)
              modal.find('.modal-body').append(data.geocountry)

        modal.modal('show')

            });

        })


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
});
