# PCAP Anonymizer as a Service

This is a simple framework that takes a pcap (cap, pcap, or pcapng) file as an upload to a non-public bucket, performs a transformation, and sends it back with a new name. Currently it just does a simple IPv4 source and destination substitution. Additional logic could be added to actually make it a useful anonymizer.

This was an exercise to learn python+flask+google app engine. Uploading a pcap to a public cloud for anonymization purposes is a questionable endeavor.
