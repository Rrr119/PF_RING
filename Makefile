all:
	cd kernel; make
	cd userland; ./configure; make
	cd drivers; make

install:
	cd userland; make install

clean:
	-cd kernel; make clean
	-cd userland; make clean
	-cd drivers; make clean
	-cd userland/snort/pfring-daq-module; make clean

snort:
	cd userland/snort/pfring-daq-module; autoreconf -ivf; ./configure; make
	cd userland/snort/pfring-daq-module-zc; autoreconf -ivf; ./configure; make

tcpdump:
	cd userland/tcpdump; ./configure; make

acceptance check:
	tests/run_flow_balance_acceptance.sh

changelog:
	git log --since={`curl -s https://github.com/ntop/PF_RING/releases | grep datetime | head -n1 | egrep -o "[0-9]+\-[0-9]+\-[0-9]+"`} --name-only --pretty=format:" - %s" > CHANGELOG.latest

documentation:
	cd doc/doxygen; doxygen Doxyfile
	cd doc; ./configure; make html

.PHONY: all install clean snort tcpdump acceptance check changelog documentation

