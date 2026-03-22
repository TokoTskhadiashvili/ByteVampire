g++ -std=c++17 -O2 ./src/main.cpp -o ./dst/bytevampire -static-libgcc -static-libstdc++ -Wl,-Bstatic -lssl -lcrypto -Wl,-Bdynamic -lpthread -ldl
