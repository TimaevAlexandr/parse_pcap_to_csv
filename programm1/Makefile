clean:
	rm -rf build
build:
	chmod +x build.sh
	./build.sh
	@echo "\n Now you can run program with \"make run pcap_file=example.pcap\""

run:
	./build/packet_classifier $(pcap_file)