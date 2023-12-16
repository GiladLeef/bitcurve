# bitcurve
Solving the SECP256K1 ECDLP for the bitcoin puzzle transaction rewards!

This is an efficient, easy to understand implementation of secp256k1 using GMP and the Baby-step-Giant-step algorithm for solving the ECDLP.

Note: I am working on a (currently closed source) CUDA version of this program that'll be much more efficient (even more then BSGS-CUDA, hopefully).

Write me on telegram for more information: @renloi.

To build the executables, install a modern GCC development envirement.
I recommand using MSYS2 and mingw-64.

Then, install gmp and then run `build.bat`. 
## Usage:
`bitcurve <public_key> <step_size> <search_size> <threads_num>` 

Simply generate list.txt using
`stepgen <T>` - T is your step size.
Test it using:

`bitcurve 033c4a45cbd643ff97d77f41ea37e843648d50fd894b864b0d52febc62f6454f7c 100 1000000 10`
