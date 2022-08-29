# Provenance Setup

We implement an audit log parser using C++, intel PT parser using C (built atop Griffin). The setup has been tested using g++ 8.4.0 and gcc 8.4.0. The required packages are as follows:

### Audit log Parser

1. Installation Path: "LIB_INSTALL_PATH"
```bash
cd provenance-analysis/AUDIT/lib
LIB_INSTALL_PATH=$PWD
```

2. g++ (optional)
```bash
wget https://ftp.gnu.org/gnu/gcc/gcc-8.4.0/gcc-8.4.0.tar.gz
tar xzvf gcc-8.4.0.tar.gz
cd gcc-8.4.0
contrib/download_prerequisites
./configure -v --build=x86_64-linux-gnu --host=x86_64-linux-gnu --target=x86_64-linux-gnu --prefix=$LIB_INSTALL_PATH/lib -enable-checking=release --enable-languages=c,c++,fortran --disable-multilib
make -j8
make install
cd ..
```

3. neo4j
```bash
sudo add-apt-repository ppa:cleishm/neo4j
sudo apt-get update
sudo apt-get install libssl-dev neo4j-client libneo4j-client-dev
```

4. libconfig
```bash
wget https://hyperrealm.github.io/libconfig/dist/libconfig-1.7.2.tar.gz
tar xzvf libconfig-1.7.2.tar.gz
cd libconfig-1.7.2/
./configure --prefix=$LIB_INSTALL_PATH
make -j8
make install
cd ../
```

5. jsoncpp
```bash
sudo apt-get install libjsoncpp-dev
```

6. nlohmann json
```bash
cd $LIB_INSTALL_PATH/include
wget https://raw.githubusercontent.com/nlohmann/json/develop/single_include/nlohmann/json.hpp
cd ../
```

7. [Neo4j setup](https://datawookie.dev/blog/2016/09/installing-neo4j-on-ubuntu-16.04) (optional)

Setup system library path (Optional)
```bash
echo export CPLUS_INCLUDE_PATH=$LIB_INSTALL_PATH/include:$CPLUS_INCLUDE_PATH >> ~/.bashrc
echo export PATH=$LIB_INSTALL_PATH/bin:$PATH >> ~/.bashrc
echo export LD_LIBRARY_PATH=$LIB_INSTALL_PATH/lib:$LIB_INSTALL_PATH/lib64:$LD_LIBRARY_PATH >> ~/.bashrc
source ~/.bashrc
```

1. driver compile
```bash
cd provenance-analysis/AUDIT/parse
make
```

### Intel PT Parser

1. distorm
```bash
cd provenance-analysis/PT/pt
wget https://github.com/gdabah/distorm/archive/refs/tags/v3.3.3.tar.gz
tar xzvf v3.3.3.tar.gz
mv distorm-3.3.3/ distorm
# no need to make
```

2. [redis setup](../provenance-analysis/PT/redis/README.md)

3. driver compile
```bash
cd provenance-analysis/PT
make
```