$(document).ready(function () {
  $('#alerts').DataTable({
    ajax: '/alerts',
    serverSide: true,
    columns: [
      {data: 'timestamp'},
      {data: 'profileid'},
      {data: 'twid'},
      {data: 'detected_ip'},
      {data: 'detection_module'},
      {data: 'detection_info'},
      {data: 'description'}
    ],
  });
});