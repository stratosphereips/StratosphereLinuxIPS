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
                    });    destroy: true,
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


$('#myModal').modal({
    show: true,
    backdrop: 'static',
    keyboard: false
})
