# bitcurve
Solving the SECP256K1 ECDLP for the bitcoin puzzle transaction rewards!

This is an efficient, easy to understand implementation of secp256k1 using GMP and the Baby-step-Giant-step algorithm for solving the ECDLP.

Note: I am working on a (currently closed source) CUDA version of this program that'll be much more efficient (even more then BSGS-CUDA, hopefully).

Write me on telegram for more information: @renloi.

To build the executables, install a modern GCC development envirement.
I recommand using MSYS2 and mingw-64.

Then, install gmp and then run `build.bat`. 
