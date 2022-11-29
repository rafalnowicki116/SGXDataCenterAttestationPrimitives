# Build docker image
```
cd ./Docker/
docker build . -f ./Dockerfile --tag ubuntu:18.04_QVL
```
# Running docker images with openssl
```
docker run -v /usr/safenet/:/usr/safenet -v /home/rnowicki/SGX/SGXDataCenterAttestationPrimitives/QuoteVerification/QVL:/QVL -it ubuntu:18.04_QVL /bin/bash
```

# Run Hello with C++ inside
## Compile library.cpp manually
```
mkdir build
cd build
powerpc-linux-gnu-g++-7 -m32 -fPIC -c -D_FORTIFY_SOURCE=0 -fno-use-cxa-atexit -o library.o ../library.cpp
```

## Copy and modified objects and libraries from powerpc/lib/gcc-cross/powerpc-linux-gnu/7.5.0 to FM/lib/standard
```
cp /usr/powerpc-linux-gnu/lib/crti.o /QVL/FM/lib/standard/
cp /usr/lib/gcc-cross/powerpc-linux-gnu/7.5.0/crtbeginT.o /QVL/FM/lib/standard/
cp /usr/lib/gcc-cross/powerpc-linux-gnu/7.5.0/crtend.o /QVL/FM/lib/standard/

cp /usr/lib/gcc-cross/powerpc-linux-gnu/7.5.0/libgcc.a /QVL/FM/lib/standard/
cp /usr/lib/gcc-cross/powerpc-linux-gnu/7.5.0/libgcc_eh.a /QVL/FM/lib/standard/
cp /usr/powerpc-linux-gnu/lib/libc.a /QVL/FM/lib/standard/
cp /usr/lib/gcc-cross/powerpc-linux-gnu/7.5.0/libstdc++.a /QVL/FM/lib/standard/
```

## Modify libc.a - remove duplicates which are in fmsupt library 
```
cd /QVL/FM/lib/standard/
powerpc-linux-gnu-objcopy ./libc.a --redefine-syms ./libc_replace_functions_names
```
## Verify if libc.a was changed correctly
```
powerpc-linux-gnu-objdump -t ./libc.a | grep "memcpy_org" | grep "text"
```

## Sign fm_hello using HSM (exit docker)
```
sudo /usr/safenet/lunaclient/bin/mkfm -f /home/rnowicki/SGX/SGXDataCenterAttestationPrimitives/QuoteVerification/QVL/FM/fm_signed/hello/fmqvl.bin -o /home/rnowicki/SGX/SGXDataCenterAttestationPrimitives/QuoteVerification/QVL/FM/fm_signed/hello/fmqvl.fm -k OCSPPartition/FMpriv
```

## Sign fm_qvl using HSM (exit docker)
```
sudo /usr/safenet/lunaclient/bin/mkfm -f /home/rnowicki/SGX/SGXDataCenterAttestationPrimitives/QuoteVerification/QVL/FM/fm_signed/hello/fmqvl.bin -o /home/rnowicki/SGX/SGXDataCenterAttestationPrimitives/QuoteVerification/QVL/FM/fm_signed/qvl/fmqvl.fm -k OCSPPartition/FMpriv
```