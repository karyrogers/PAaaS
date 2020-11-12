import os, random
from io import BytesIO
from flask import Flask, abort, render_template, request, make_response, redirect, url_for, send_from_directory, send_file
from werkzeug.utils import secure_filename
from scapy.all import *
from ipaddress import IPv4Address
from google.cloud import storage

app = Flask(__name__)

# set in app.yaml
CLOUD_STORAGE_BUCKET = os.environ['CLOUD_STORAGE_BUCKET']
# only allow these file extensions
app.config['ALLOWED_EXTENSIONS'] = ['cap', 'pcap', 'pcapng']
# only accept files under 10MB
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024

@app.errorhandler(413)
def too_large(e):
    return "File is too large", 413
    
def allowed_file(filename):
    return '.' in filename and \
            filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def random_ipv4_address(seed):
    random.seed(seed)
    return str(IPv4Address(random.getrandbits(32)))

def anonymize_pcap(pcap):
    # keep track of seen IPs for consistent substitution
    ipmap = {}
    # read in the pcap
    pkts = rdpcap(io.BytesIO(pcap.read()))
    for pkt in pkts:
        src = pkt[IP].src
        dst = pkt[IP].dst

        # if we've seen this ip before, just save the substitution
        if src in ipmap:
            pkt[IP].src = ipmap[src]
        # otherwise create a new random IP. this needs a better seed
        else:
            pkt[IP].src = random_ipv4_address(str(src))
            ipmap[src] = pkt[IP].src
        if dst in ipmap:
            pkt[IP].dst = ipmap[dst]
        else:
            pkt[IP].dst = random_ipv4_address(str(dst))
            ipmap[dst] = pkt[IP].dst

        # delete the IP checksum so it gets recalc'ed later
        del pkt[IP].chksum

    # write all the pkts to a buffer without closing the handle and return it
    buf = io.BytesIO()
    PcapWriter(buf).write(pkts)
    return buf

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/', methods=['POST'])
def upload_files():
    pcap = request.files['file']
    # sanitize the filename
    filename = secure_filename(pcap.filename)
    if filename != '':
        # check the file extension
        if not allowed_file(filename):
            return "Invalid file", 400

        # anonymize and create a new filename
        anonpkts = anonymize_pcap(pcap)
        anonpcap = os.path.splitext(filename)[0] + '-anon' + os.path.splitext(filename)[1]

        # upload to the default bucket
        gcs = storage.Client()
        bucket = gcs.get_bucket(CLOUD_STORAGE_BUCKET)
        blob = bucket.blob(anonpcap)
        blob.upload_from_string(anonpkts.getvalue(), content_type=pcap.content_type)

        # send user to the download page
        return render_template('success.html', downloadlink=url_for('uploaded_file',filename=anonpcap))

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    # read the anonymized pcap from the bucket and send it to the browser
    gcs = storage.Client()
    bucket = gcs.get_bucket(CLOUD_STORAGE_BUCKET)
    blob = bucket.blob(filename)
    return send_file(io.BytesIO(blob.download_as_string()), as_attachment=True, attachment_filename=filename)

if __name__ == '__main__':
    # This is used when running locally. Gunicorn is used to run the
    # application on Google App Engine. See entrypoint in app.yaml.
    app.run(host='127.0.0.1', port=8080, debug=True)
