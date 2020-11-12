<html>
	<head>
		<title>PCAP Upload</title>
		<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/dropzone/5.7.1/min/dropzone.min.css">
	</head>
	<body>
		<h1>PCAP Upload</h1>
		<form action="{{ url_for('upload_files') }}" class="dropzone">
		</form>
		<script src="https://cdnjs.cloudflare.com/ajax/libs/dropzone/5.7.1/min/dropzone.min.js"></script>
	</body>
</html>
