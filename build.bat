mkdir build
gcc stepgen.c -lgmp -O3 -o build/stepgen
gcc bitcurve.c -lgmp -O3 -o build/bitcurve