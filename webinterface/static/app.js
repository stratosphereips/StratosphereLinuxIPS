const headers2 = {
    headers: {'Content-Type': 'application/json'}
}

fetch("/info", {
        method: "GET",
        headers: headers2
        }).then(response => response.json())
        .then(data => {
                        document.getElementById("slips_version").textContent="Slips "+data['slips_version'];
                        document.getElementById("fileName").textContent=data['name'];
                        document.getElementById("fileSize").textContent=data['size_in_MB'];
                        document.getElementById("analysisStart").textContent=data['analysis_start'];
                        document.getElementById("analysisEnd").textContent=data['analysis_end'];
                    });

$("#table_choose_redis").DataTable({
    destroy: true,
    searching: false,
    ajax: '/redis',
    "bInfo": false,
    scrollY: 100,
    paging: false,
    select:true,
    columns: [
        { data: 'filename' },
        { data: 'redis_port' }
    ],
    "fnInitComplete": function( settings, json ) {
        $('#table_choose_redis tbody tr:eq(0)').click();
    }
})


$('#modal_choose_redis').modal({
    show: false,
    backdrop: 'static',
    keyboard: false
})

$('#button_choose_db').click(function(){
    let data = $('#table_choose_redis').DataTable().row( { selected: true } ).data()
    $('#modal_choose_redis .close').click() // close modal by imitating the close button click. $('#myModal').hide() does not work
    let link = "/db/" + data['redis_port']
    $.get( link );
    window.location.reload();
});


